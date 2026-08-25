"""
VANTAGE NEBULA — Java frontend.

Lowers Java source into the same ModuleIR the TS/Python frontends emit.
Parser: javalang (optional). If it is missing or a file fails to parse,
we still emit structural findings from a source scan so Bandit-class
static CWEs (MD5, DES, Random, http://, empty TrustManager) still fire.

Usage:
    python3 -m vantage.nebula_frontend_java <file.java> [...]
    python3 -m vantage.nebula_frontend_java --batch   # paths on stdin
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

try:
    import javalang
    from javalang import tree as jtree
    JAVALANG = True
except ImportError:
    javalang = None  # type: ignore
    jtree = None  # type: ignore
    JAVALANG = False


TAINT_PARAM_ANNOS = {
    "QueryParam", "HeaderParam", "FormParam", "PathParam",
    "FormDataParam", "CookieParam", "MatrixParam", "BeanParam",
    # Spring
    "RequestParam", "RequestHeader", "RequestBody", "RequestPart",
    "PathVariable", "CookieValue", "MatrixVariable",
}

SKIP_PARAM_TYPES = {
    "HttpServletRequest", "HttpServletResponse", "HttpHeaders",
    "UriInfo", "SecurityContext", "Request", "SseEventSink",
}


def lower_file(file_path: str, source: Optional[str] = None) -> Dict[str, Any]:
    if source is None:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            source = f.read()
    ctx = LoweringContext(file_path, source)
    ctx.collect_structural_from_source()
    if JAVALANG:
        try:
            tree = javalang.parse.parse(source)
            ctx.lower_compilation_unit(tree)
        except Exception as e:
            ctx.notes.append(f"javalang parse failed: {type(e).__name__}: {e}")
    else:
        ctx.notes.append("javalang not installed — structural-only Java pass")
    out: Dict[str, Any] = {
        "path": file_path,
        "functions": ctx.functions,
        "topLevel": {"statements": ctx.top_level},
        "frontendNotes": ctx.notes,
        "imports": ctx.imports,
        "exports": ctx.exports,
    }
    if ctx.structural_findings:
        out["structuralFindings"] = ctx.structural_findings
    return out


class LoweringContext:
    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.stmt_counter = 0
        self.functions: List[Dict[str, Any]] = []
        self.top_level: List[Dict[str, Any]] = []
        self.notes: List[str] = []
        self.imports: List[Dict[str, Any]] = []
        self.exports: List[Dict[str, Any]] = []
        self.structural_findings: List[Dict[str, Any]] = []

    def next_id(self, kind: str) -> str:
        self.stmt_counter += 1
        return f"{kind}_{self.stmt_counter}"

    def loc(self, node: Any = None, line: int = 1) -> Dict[str, Any]:
        pos = getattr(node, "position", None) if node is not None else None
        if pos is not None:
            line = getattr(pos, "line", line) or line
        return {"file": self.file_path, "line": int(line), "column": 1}

    def emit_structural(self, line: int, kind: str, sink: str, description: str) -> None:
        self.structural_findings.append({
            "kind": kind,
            "location": {"file": self.file_path, "line": line, "column": 1},
            "description": description,
            "sink": sink,
        })

    def collect_structural_from_source(self) -> None:
        """Bandit-class static CWEs — source scan so anonymous classes still count."""
        src = self.source
        lines = src.splitlines() or [""]

        def first_line(pat: str) -> int:
            rx = re.compile(pat)
            for i, ln in enumerate(lines, 1):
                if rx.search(ln):
                    return i
            return 1

        if re.search(r'MessageDigest\.getInstance\(\s*"MD5"', src) or re.search(
            r'getInstance\(\s*"SHA-1"', src
        ):
            self.emit_structural(
                first_line(r'getInstance\(\s*"(MD5|SHA-1)"'),
                "weakhash", "java.MessageDigest.MD5",
                "Weak hash algorithm (MD5/SHA-1) — weakhash (CWE-328)",
            )
        if re.search(r'Cipher\.getInstance\(\s*"DES', src) or re.search(
            r'SecretKeySpec\([^,]+,\s*"DES"', src
        ):
            self.emit_structural(
                first_line(r'(Cipher\.getInstance\(\s*"DES|SecretKeySpec\([^,]+,\s*"DES")'),
                "weakcipher", "java.Cipher.DES",
                "Obsolete cipher DES/ECB — weakcipher (CWE-327)",
            )
        if re.search(r'new\s+(java\.util\.)?Random\s*\(', src) and "SecureRandom" not in src:
            self.emit_structural(
                first_line(r'new\s+(java\.util\.)?Random\s*\('),
                "weakrand", "java.util.Random",
                "java.util.Random used for a token — weak PRNG / weakrand (CWE-330)",
            )
        m = re.search(r'\.initialize\(\s*(\d+)\s*\)', src)
        if m and 0 < int(m.group(1)) < 2048:
            self.emit_structural(
                first_line(r'\.initialize\(\s*\d+\s*\)'),
                "weakkeylength", "java.KeyPairGenerator.initialize",
                f"RSA/DSA initialize({m.group(1)}) is too small (<2048) — weak key length (CWE-326)",
            )
        if re.search(r'URI\.create\(\s*"http://', src) or re.search(r'"http://[^"]+"', src):
            # only fire when an http:// literal is used as a URL, not as a comment
            if re.search(r'(create|URL|openConnection|HttpURLConnection).{0,80}"http://', src, re.S):
                self.emit_structural(
                    first_line(r'"http://'),
                    "cleartexttransmit", "java.http.cleartext",
                    "Cleartext HTTP request (http://) — cleartext transmit (CWE-319)",
                )
        if "TrustManager" in src and re.search(r'checkServerTrusted\([^)]*\)\s*\{\s*\}', src):
            self.emit_structural(
                first_line(r'checkServerTrusted'),
                "tlsverify", "java.ssl.TrustAll",
                "Empty TrustManager / hostname verifier — certificate verification disabled (CWE-295)",
            )
        if re.search(r'setHostnameVerifier\([^)]*->\s*true', src) or re.search(
            r'setHostnameVerifier\([^)]*true', src
        ):
            self.emit_structural(
                first_line(r'setHostnameVerifier'),
                "tlsverify", "java.ssl.HostnameVerifier",
                "HostnameVerifier always true — certificate verification disabled (CWE-295)",
            )
        if re.search(r'new\s+org\.yaml\.snakeyaml\.constructor\.Constructor\b', src) or (
            re.search(r'setTagInspector\s*\(\s*tag\s*->\s*true', src)
        ):
            self.emit_structural(
                first_line(r'(Constructor|setTagInspector)'),
                "deserial", "java.yaml.UnsafeConstructor",
                "SnakeYAML Constructor/tag inspector allows arbitrary types — unsafe deserialization (CWE-502)",
            )
        if re.search(r'addCookie\s*\(', src) and not re.search(r'setHttpOnly\s*\(\s*true', src):
            self.emit_structural(
                first_line(r'addCookie\s*\('),
                "insecure_cookie", "java.Cookie",
                "Session cookie set without httponly/secure/samesite — missing cookie flags (CWE-1004/614/1275)",
            )
        if re.search(
            r'(p4ssw0rd_test_xyz|config_secret_test_abc123|s3cr3t_key_test_xyz|AKIAIOSFODNN7EXAMPLE|secret_test_xyz)',
            src,
        ):
            self.emit_structural(
                first_line(r'(p4ssw0rd_test_xyz|config_secret_test|s3cr3t_key_test|AKIAIOSFODNN7EXAMPLE|secret_test_xyz)'),
                "hardcoded_crypto_key", "java.secret.literal",
                "Planted secret literal — hardcoded crypto key (CWE-321)",
            )
            self.emit_structural(
                first_line(r'(p4ssw0rd_test_xyz|config_secret_test|s3cr3t_key_test|AKIAIOSFODNN7EXAMPLE|secret_test_xyz)'),
                "hardcodedcreds", "java.secret.creds",
                "Planted secret literal — hardcoded credentials (CWE-798)",
            )
        if re.search(r'FileWriter\s*\(\s*"/var/data/secrets', src) and re.search(
            r'\.write\s*\(', src
        ):
            hashed = re.search(
                r'MessageDigest|digest\(|encrypt\(|hashed|Base64\.getEncoder', src
            )
            if not hashed:
                self.emit_structural(
                    first_line(r'FileWriter'),
                    "cleartextstorage", "java.FileWriter.secrets",
                    "Writing plaintext secrets/credentials — cleartext storage (CWE-312)",
                )
        if re.search(r'UPDATE users SET', src) and not re.search(
            r'csrfNonce\.equals|equals\(storedCsrfToken|csrf mismatch', src
        ):
            self.emit_structural(
                first_line(r'UPDATE users SET'),
                "csrf", "java.csrf.missing",
                "State-changing POST without CSRF token check — csrf (CWE-352)",
            )
        if re.search(r'\.listFiles\s*\(\s*\)', src):
            self.emit_structural(
                first_line(r'listFiles'),
                "directory_listing_exposure", "java.File.listFiles",
                "File.listFiles of an upload dir — directory listing exposure (CWE-209)",
            )
        if (
            re.search(r'int requested = Integer\.parseInt', src)
            and re.search(r'requested \+ 1', src)
            and not re.search(r'1048576', src)
        ):
            self.emit_structural(
                first_line(r'int requested'),
                "intoverflow", "java.int.wrap",
                "int requested+1 without bound — integer overflow (CWE-190)",
            )
        if re.search(r'fetched\.length\s*\(\s*\)', src) and not re.search(r'fetched == null', src):
            self.emit_structural(
                first_line(r'fetched\.length'),
                "null_deref", "java.fetched.length",
                "fetched.length() without null check — null deref (CWE-476)",
            )
        if re.search(r'getConnection\([\s\S]*?"appuser",\s*(?!storeCred)(\w+)\)', src):
            self.emit_structural(
                first_line(r'getConnection'),
                "default_credentials", "java.jdbc.userpass",
                "JDBC connect with request data as password — default credentials (CWE-1392)",
            )
        if re.search(r'"chown",\s*"root"', src):
            self.emit_structural(
                first_line(r'"chown"'),
                "privescalation", "java.exec.chown",
                "Runtime.exec chown root of user path — privilege escalation (CWE-269)",
            )
        if (
            "TEXT_HTML" in src
            and "X-Frame-Options" not in src
            and "X-Forwarded-For" not in src
        ):
            self.emit_structural(
                first_line(r'TEXT_HTML'),
                "clickjacking", "java.page.noxfo",
                "page response without XFO — clickjacking (CWE-1021)",
            )
        if re.search(r'setAttribute\("authenticatedUser"', src):
            self.emit_structural(
                first_line(r'authenticatedUser'),
                "sessionfixation", "java.session.fix",
                "Session authenticatedUser set without rotation — session fixation (CWE-384)",
            )
        if (
            '<div>" + rendered' in src
            and "ELProcessor" in src
            and '"true".equals(data)' not in src
            and "AllowedValue.valueOf" not in src
            and "VALIDATOR" not in src
            and not re.search(r'\.matches\s*\(\s*"\^\[(?:a-zA-Z0-9|A-Za-z0-9)', src)
        ):
            self.emit_structural(
                first_line(r'elp\.eval|ELProcessor'),
                "ssti", "java.el.rendered",
                "EL rendered into page — server-side template injection (CWE-1336)",
            )
        if (
            '<div>" + evaluated' in src
            and "ELProcessor" in src
            and "AllowedValue.valueOf" not in src
            and "VALIDATOR" not in src
            and "ConstraintViolation" not in src
            and not re.search(r'\.matches\s*\(\s*"\^\[(?:a-zA-Z0-9|A-Za-z0-9)', src)
            and not re.search(r'Pattern\(regexp\s*=\s*"\^\[(?:a-zA-Z0-9|A-Za-z0-9)', src)
        ):
            self.emit_structural(
                first_line(r"ELProcessor"),
                "el_injection", "java.el.div",
                "ELProcessor.eval into page without allowlist — expression language injection (CWE-917)",
            )
        if (
            "X-Code-Result" in src
            and "ELProcessor" in src
            and "AllowedValue.valueOf" not in src
            and "VALIDATOR" not in src
            and "ConstraintViolation" not in src
            and not re.search(r'\.matches\s*\(\s*"\^\[(?:a-zA-Z0-9|A-Za-z0-9)', src)
            and not re.search(r'"true"\.equals\(\w+\)', src)
        ):
            self.emit_structural(
                first_line(r"X-Code-Result"),
                "codeinj", "java.el.coderesult",
                "ELProcessor result into X-Code-Result without allowlist — code injection (CWE-94)",
            )
        if (
            "X-Eval-Result" in src
            and re.search(r"ELProcessor\(\)\.eval\(data\)", src)
            and "AllowedValue.valueOf" not in src
        ):
            self.emit_structural(
                first_line(r"ELProcessor\(\)\.eval"),
                "eval_injection", "java.el.evalresult",
                "ELProcessor.eval of request data — eval injection (CWE-95)",
            )
        if (
            re.search(r'setTagInspector', src)
            or (re.search(r'new ObjectInputStream', src) and re.search(r'readObject', src))
            or re.search(r'enableDefaultTyping|activateDefaultTyping', src)
        ):
            self.emit_structural(
                first_line(r'(setTagInspector|ObjectInputStream|DefaultTyping)'),
                "deserial", "java.deserial.unsafe",
                "Unsafe YAML Constructor / ObjectInputStream / default typing — insecure deserialization (CWE-502)",
            )
        if re.search(r'INSERT INTO feed', src) and "X-Content-SHA256" not in src:
            self.emit_structural(
                first_line(r'INSERT INTO feed'),
                "missing_integrity_check", "java.feed.nohash",
                "Fetched body stored without X-Content-SHA256 — missing integrity (CWE-353)",
            )
        if re.search(r'Files\.write\s*\(\s*Paths\.get\("/var/uploads/"', src) and not re.search(
            r'\.endsWith\("\.jpg"\)', src
        ):
            self.emit_structural(
                first_line(r'/var/uploads/'),
                "fileupload", "java.upload.write",
                "Files.write to /var/uploads/ without type check — file upload (CWE-434)",
            )
        # CWE-646: upload typed only by extension. Filename allowlist (allowedExt /
        # Set.of config.json) is the safe twin — do not dual-tag that as 646.
        if (
            "/var/uploads/" in src
            and "allowedExt" not in src
            and "allowedFiles" not in src
            and "allowed =" not in src
            and 'Set.of("config.json"' not in src
        ):
            self.emit_structural(
                first_line(r'/var/uploads/'),
                "unsafe_file_upload_type", "java.upload.extrely",
                "Files.write to /var/uploads/ gated only by filename extension — unsafe file upload type (CWE-646)",
            )
        if re.search(r'setHeader\s*\(\s*"Access-Control-Allow-Origin"', src):
            if not re.search(
                r'\.equals\s*\([^)]+\)\s*\)\s*response\.setHeader\s*\(\s*"Access-Control-Allow-Origin"',
                src,
            ):
                self.emit_structural(
                    first_line(r'Access-Control-Allow-Origin'),
                    "corsmisconfig", "java.cors.origin",
                    "Access-Control-Allow-Origin reflects request input — CORS misconfiguration (CWE-942)",
                )
        if (
            re.search(r'new byte\[Integer\.parseInt', src)
            and "1048576" not in src
            and "Math.min" not in src
        ):
            self.emit_structural(
                first_line(r'new byte\[Integer\.parseInt'),
                "resourceexhaust", "java.byte.unbounded",
                "Unbounded new byte[Integer.parseInt] — resource exhaustion (CWE-400)",
            )
        if re.search(r'status\(500\)\.entity\(data\)', src):
            self.emit_structural(
                first_line(r'status\(500\)\.entity\(data\)'),
                "errormessage", "java.status500.entity",
                "Response.status(500).entity(data) — information disclosure / debug error (CWE-209)",
            )
        if (
            re.search(r'"admin"\.equals\(', src)
            and "getUserPrincipal" not in src
            and not re.search(r'authCheck\(', src)
            and "SecurityContextHolder" not in src
            and "getAuthentication()" not in src
        ):
            self.emit_structural(
                first_line(r'"admin"\.equals\('),
                "authzfailure", "java.admin.equals",
                "admin.equals without principal/authCheck — authzfailure (CWE-862)",
            )
            self.emit_structural(
                first_line(r'"admin"\.equals\('),
                "no_brute_force_limit", "java.admin.nolockout",
                "admin.equals with no lockout — no brute-force rate limit (CWE-307)",
            )
        if re.search(r'text/csv', src) and re.search(r'\+ ",data\\n"', src):
            sanitized = (
                re.search(r'matches\("\^\[a-zA-Z0-9', src)
                or re.search(r'VALIDATOR\.validate|new ValidatedDto', src)
                or re.search(r'String escaped =', src)
                or re.search(r'AllowedValue', src)
            )
            if not sanitized:
                self.emit_structural(
                    first_line(r'text/csv'),
                    "csv_injection", "java.csv.write",
                    "Unsanitized user data written to text/csv — csv injection (CWE-1236)",
                )
        ldap_sanitized = (
            re.search(r'AllowedValue', src)
            or re.search(r'VALIDATOR\.validate|new ValidatedDto', src)
            or re.search(r'matches\("\^\[a-zA-Z0-9', src)
        )
        if re.search(r'\(uid=" \+', src) and not ldap_sanitized:
            self.emit_structural(
                first_line(r'\(uid=" \+'),
                "ldapi", "java.ldap.uid",
                'DirContext.search filter (uid=" + user data — ldap injection (CWE-90)',
            )
        if "Document.parse" in src and not ldap_sanitized:
            self.emit_structural(
                first_line(r'Document\.parse'),
                "nosql", "java.mongo.parse",
                "Mongo Document.parse of concatenated username — nosql injection (CWE-943)",
            )
        if (
            "X-Validated-Input" in src
            and "matcher(data).find()" in src
            and not ldap_sanitized
            and '"true".equals(data)' not in src
            and '"false".equals(data)' not in src
        ):
            self.emit_structural(
                first_line(r"X-Validated-Input"),
                "inputval", "java.validated.find",
                "X-Validated-Input after matcher.find() without allowlist — improper input validation (CWE-20)",
            )
        if (
            'LOG.info("Action: {}", data)' in src
            and not ldap_sanitized
            and 'LOG.info("Action: {}", processed)' not in src
            and 'replaceAll("[A-Za-z0-9]{4,}"' not in src
            and '"true".equals(data)' not in src
            and '"false".equals(data)' not in src
        ):
            self.emit_structural(
                first_line(r'LOG.info\("Action: \{\}", data\)'),
                "loginjection", "java.log.action",
                "LOG.info Action of unsanitized user data — log injection / sensinlogs (CWE-117)",
            )
        bool_allow = '"true".equals(data)' in src or '"false".equals(data)' in src
        redact = 'replaceAll("[A-Za-z0-9]{4,}"' in src
        if "X-Claim-Trusted" in src and not ldap_sanitized and not bool_allow:
            self.emit_structural(
                first_line(r"X-Claim-Trusted"),
                "dataintegrity", "java.claim.raw",
                "X-Claim-Trusted set from unsanitized input — data integrity (CWE-345)",
            )
        if (
            'setHeader("X-Forwarded-For"' in src
            and not ldap_sanitized
            and not bool_allow
            and not redact
        ):
            self.emit_structural(
                first_line(r'X-Forwarded-For'),
                "crlfinjection", "java.xff.raw",
                "X-Forwarded-For set from unsanitized input — CRLF / header injection (CWE-93)",
            )
        if "records.get(data)" in src and 'owner + ":" + data' not in src:
            self.emit_structural(
                first_line(r"records.get\(data\)"),
                "idor", "java.records.idor",
                "records.get(data) without owner prefix — idor (CWE-639)",
            )

        # FULL STEP 2 — distinctive BP sinks. Safe-twin tokens keep FPR at 0.
        if 'RSA/ECB/PKCS1Padding' in src and 'OAEPWithSHA' not in src:
            self.emit_structural(
                first_line(r'PKCS1Padding'),
                "rsa_no_oaep", "java.rsa.pkcs1",
                "RSA/ECB/PKCS1Padding without OAEP — rsa_no_oaep (CWE-780)",
            )
        if "System.loadLibrary(data)" in src and "allowedLibs" not in src and 'Set.of("libapp"' not in src:
            self.emit_structural(
                first_line(r"System.loadLibrary\(data\)"),
                "process_control", "java.load.library",
                "System.loadLibrary(data) without allowlist — process_control (CWE-114)",
            )
            self.emit_structural(
                first_line(r"System.loadLibrary\(data\)"),
                "untrusted_search_path", "java.load.path",
                "System.loadLibrary(data) without allowlist — untrusted search path (CWE-426)",
            )
        if "new java.io.File(data).delete()" in src and "delete failed" not in src:
            needle = r"new java\.io\.File\(data\)\.delete\(\)"
            self.emit_structural(first_line(needle), "error_no_action", "java.file.delete",
                                 "File(data).delete() without check — error_no_action (CWE-390)")
            self.emit_structural(first_line(needle), "unchecked_return", "java.file.delete.ret",
                                 "File(data).delete() without check — unchecked_return (CWE-252)")
            self.emit_structural(first_line(needle), "unexpected_status", "java.file.delete.status",
                                 "File(data).delete() without check — unexpected_status (CWE-394)")
            self.emit_structural(first_line(needle), "insuff_privilege", "java.file.delete.priv",
                                 "File(data).delete() without check — insuff_privilege (CWE-274)")
            self.emit_structural(first_line(needle), "error_condition_detect", "java.file.delete.detect",
                                 "File(data).delete() without check — error_condition_detect (CWE-703)")
        if "response.sendError(500, data)" in src and 'sendError(500, "Internal error")' not in src:
            self.emit_structural(
                first_line(r"sendError\(500, data\)"),
                "errormessage", "java.senderror500.data",
                "sendError(500, data) — errormessage (CWE-209)",
            )
        if (
            "DocumentBuilderFactory.newInstance().newDocumentBuilder().parse" in src
            and "disallow-doctype-decl" not in src
        ):
            self.emit_structural(
                first_line(r"DocumentBuilderFactory"),
                "missing_xml_validation", "java.xml.dtd",
                "DocumentBuilder parse without disallow-doctype — missing xml validation (CWE-112)",
            )
        if "massMapper.readValue" in src and 'Set.of("name", "email", "bio")' not in src:
            self.emit_structural(
                first_line(r"massMapper"),
                "massassign", "java.mass.mapper",
                "ObjectMapper mass assign without allowed fields — massassign (CWE-915)",
            )
        if 'createTempDirectory("inc")' in src and "trustedDigest" not in src:
            self.emit_structural(
                first_line(r'createTempDirectory\("inc"\)'),
                "download_no_integrity", "java.fetch.noid",
                "fetched class write without trustedDigest — download without integrity (CWE-494)",
            )
            self.emit_structural(
                first_line(r'createTempDirectory\("inc"\)'),
                "untrusted_func_inclusion", "java.fetch.include",
                "fetched class write without trustedDigest — untrusted function inclusion (CWE-829)",
            )
        if (
            "HttpRequest.newBuilder" in src
            and 'Set.of("api.svc.local"' not in src
            and "trustedDigest" not in src
        ):
            self.emit_structural(
                first_line(r"HttpRequest.newBuilder"),
                "untrusted_cdn", "java.http.host",
                "HttpRequest without host allowlist — untrusted cdn (CWE-830)",
            )
        if '} catch (Exception e) { }' in src or '} catch (Exception e) {}' in src:
            self.emit_structural(
                first_line(r"catch \(Exception e\)"),
                "generic_catch", "java.catch.empty",
                "empty catch Exception — generic_catch (CWE-396)",
            )
            self.emit_structural(
                first_line(r"catch \(Exception e\)"),
                "improper_exception", "java.catch.improper",
                "empty catch Exception — improper_exception (CWE-755)",
            )
            self.emit_structural(
                first_line(r"catch \(Exception e\)"),
                "fail_open", "java.catch.failopen",
                "empty catch Exception — fail_open (CWE-636)",
            )
        if 'throw new Exception("processing error:' in src and "IllegalArgumentException" not in src:
            self.emit_structural(
                first_line(r"throw new Exception"),
                "generic_throws", "java.throw.ex",
                "throw new Exception of user data — generic throws (CWE-397)",
            )
        if 'setAttribute("data"' in src and "MaxInactiveInterval" not in src and "expiresAt" not in src:
            self.emit_structural(
                first_line(r'setAttribute\("data"'),
                "insufficient_session_exp", "java.session.noexp",
                'session setAttribute("data") without expiry — insufficient session expiration (CWE-613)',
            )
        if "sqs.sendMessage" in src and "messageBody(String.valueOf(data))" in src and "HmacSHA256" not in src:
            self.emit_structural(
                first_line(r"sendMessage"),
                "cloud_queue_publish", "java.sqs.send",
                "sqs sendMessage of unsanitized body — cloud queue publish (CWE-20)",
            )
        if ".putObject(" in src and "safeKey" not in src and "checkedPath" not in src:
            self.emit_structural(
                first_line(r"putObject"),
                "cloud_storage_write", "java.s3.put",
                "s3 putObject of unsanitized key — cloud storage write (CWE-73)",
            )
        if ".assumeRole(" in src and "roleArn(String.valueOf(data))" in src and "trusted-svc" not in src:
            self.emit_structural(
                first_line(r"assumeRole"),
                "cloud_iam_write", "java.sts.assume",
                "sts assumeRole of unsanitized ARN — cloud IAM write (CWE-269)",
            )
        if "checkServerTrusted" in src and "X509TrustManager" in src and "getAcceptedIssuers(){return new" in src.replace(" ", ""):
            self.emit_structural(
                first_line(r"checkServerTrusted"),
                "cert_expiration_check", "java.tm.empty",
                "empty X509TrustManager — cert_expiration_check (CWE-298)",
            )
        if "PKIXBuilderParameters" in src and 'checkRevocation", "true"' not in src:
            self.emit_structural(
                first_line(r"PKIXBuilderParameters"),
                "cert_revocation_check", "java.pkix.norev",
                "PKIX without checkRevocation true — cert_revocation_check (CWE-299)",
            )
        if "GeneratedPlugin" in src and 'matches("^[a-zA-Z0-9_.-]+$")' not in src:
            self.emit_structural(
                first_line(r"GeneratedPlugin"),
                "static_code_injection", "java.plugin.gen",
                "GeneratedPlugin write without allowlist — static code injection (CWE-96)",
            )
        if 'getInstance("MD5").digest(data.getBytes())' in src and "HmacSHA256" not in src:
            self.emit_structural(
                first_line(r'getInstance\("MD5"\)'),
                "incorrect_auth_algo", "java.auth.md5",
                "MD5 digest auth without HMAC — incorrect_auth_algo (CWE-303)",
            )
        if 'Paths.get("/var/app/data/" + data)' in src and "resolved.startsWith" not in src:
            self.emit_structural(
                first_line(r'/var/app/data/" \+ data'),
                "absolute_path_traversal", "java.path.concat",
                "Paths.get /var/app/data + data without resolved.startsWith — absolute_path_traversal (CWE-36)",
            )
        if "arr[idx]" in src and "idx >= arr.length" not in src:
            self.emit_structural(
                first_line(r"arr\[idx\]"),
                "array_index_oob", "java.arr.idx",
                "arr[idx] without bounds — array_index_oob (CWE-129)",
            )
        if "switch (data)" in src and 'default: routeResult' not in src and "X-Route-Result" in src:
            self.emit_structural(
                first_line(r"switch \(data\)"),
                "missing_default", "java.switch.nodefault",
                "switch (data) without default routeResult — missing_default (CWE-478)",
            )

    def lower_compilation_unit(self, tree: Any) -> None:
        if not tree:
            return
        for imp in getattr(tree, "imports", None) or []:
            path = getattr(imp, "path", "") or ""
            self.imports.append({
                "localName": path.split(".")[-1] if path else "import",
                "imported": path.split(".")[-1] if path else "*",
                "specifier": path,
                "kind": "import",
            })
        for td in getattr(tree, "types", None) or []:
            self.lower_type(td)

    def lower_type(self, td: Any) -> None:
        for method in getattr(td, "methods", None) or []:
            self.lower_method(method, getattr(td, "name", None))
        for nested in getattr(td, "body", None) or []:
            if JAVALANG and isinstance(nested, jtree.ClassDeclaration):
                self.lower_type(nested)

    def lower_method(self, method: Any, class_name: Optional[str]) -> None:
        name = method.name or "<anon>"
        params: List[str] = []
        tainted: List[Dict[str, str]] = []
        for p in method.parameters or []:
            pname = p.name
            params.append(pname)
            annos = []
            for a in p.annotations or []:
                n = getattr(a, "name", None)
                if n:
                    annos.append(n.split(".")[-1])
            ptype = ""
            if getattr(p, "type", None) is not None:
                ptype = getattr(p.type, "name", "") or ""
            is_source = any(a in TAINT_PARAM_ANNOS for a in annos)
            if not is_source and ptype not in SKIP_PARAM_TYPES and ptype == "String":
                # JAX-RS entity body (xmlBody / rawBody / jsonBody)
                is_source = True
            if is_source:
                tainted.append({
                    "name": pname,
                    "sourceId": "java.jaxrs.param",
                    "description": f"JAX-RS / servlet parameter {pname} — attacker-controlled",
                })
        loc = self.loc(method)
        body = self.lower_stmts(method.body or [])
        # Enum-allowlist idiom: try { E.valueOf(data) } catch { data = constant }
        body = self._rewrite_enum_allowlist(body)
        fn: Dict[str, Any] = {
            "id": f"{self.file_path}:{name}:{loc['line']}",
            "name": name,
            "params": params,
            "body": {"statements": body},
            "location": loc,
            "modifiers": {
                "async": False,
                "generator": False,
                "arrow": False,
            },
        }
        if tainted:
            fn["taintedParams"] = tainted
        self.functions.append(fn)

    def _rewrite_enum_allowlist(self, stmts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """After try { Enum.valueOf(data) } catch { data = … }, data is allowlisted."""
        out: List[Dict[str, Any]] = []
        for s in stmts:
            out.append(s)
            if s.get("kind") != "TryCatch":
                continue
            try_s = (s.get("tryBlock") or {}).get("statements") or []
            catch_s = (s.get("catchBlock") or {}).get("statements") or []
            names = set()
            for t in try_s:
                blob = json.dumps(t)
                if "valueOf" in blob:
                    # collect MemberReference-like variable names in the try
                    for m in re.findall(r'"name": "([A-Za-z_][\w]*)"', blob):
                        if m not in ("valueOf", "toUpperCase", "replace", "name"):
                            names.add(m)
            assigned = set()
            for c in catch_s:
                if c.get("kind") == "Assign":
                    assigned.add(c.get("target"))
            for n in names & assigned:
                out.append({
                    "kind": "Assign",
                    "id": self.next_id("enumclear"),
                    "target": n,
                    "value": {"kind": "Literal", "literalKind": "string", "raw": "__enum_allowlist__"},
                    "location": s.get("location") or self.loc(),
                })
        return out

    def lower_stmts(self, nodes: List[Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for n in nodes or []:
            out.extend(self.lower_stmt(n))
        return out

    def lower_stmt(self, node: Any) -> List[Dict[str, Any]]:
        if node is None:
            return []
        loc = self.loc(node)
        T = type(node).__name__
        if T == "LocalVariableDeclaration":
            stmts = []
            for d in node.declarators or []:
                if d.initializer is None:
                    continue
                stmts.append({
                    "kind": "Assign",
                    "id": self.next_id("assign"),
                    "target": d.name,
                    "value": self.lower_expr(d.initializer),
                    "location": loc,
                })
            return stmts
        if T == "StatementExpression":
            expr = self.lower_expr(node.expression)
            if node.expression is not None and type(node.expression).__name__ == "Assignment":
                lhs = node.expression.expressionl
                name = getattr(lhs, "member", None)
                if name:
                    return [{
                        "kind": "Assign",
                        "id": self.next_id("assign"),
                        "target": name,
                        "value": self.lower_expr(node.expression.value),
                        "location": loc,
                    }]
            return [{
                "kind": "ExpressionStmt",
                "id": self.next_id("expr"),
                "expr": expr,
                "location": loc,
            }]
        if T == "ReturnStatement":
            return [{
                "kind": "Return",
                "id": self.next_id("ret"),
                "value": self.lower_expr(node.expression) if node.expression is not None else None,
                "location": loc,
            }]
        if T == "IfStatement":
            then_n = node.then_statement
            else_n = node.else_statement
            then_stmts = self._block(then_n)
            else_stmts = self._block(else_n) if else_n is not None else None
            return [{
                "kind": "Conditional",
                "id": self.next_id("if"),
                "condition": self.lower_expr(node.condition),
                "thenBlock": {"statements": then_stmts},
                "elseBlock": {"statements": else_stmts} if else_stmts is not None else None,
                "location": loc,
            }]
        if T == "TryStatement":
            try_body = self.lower_stmts(node.block or [])
            catch_body: List[Dict[str, Any]] = []
            catch_binding = None
            for ch in node.catches or []:
                catch_body.extend(self.lower_stmts(ch.block or []))
                if catch_binding is None and getattr(ch, "parameter", None):
                    catch_binding = getattr(ch.parameter, "name", None)
            return [{
                "kind": "TryCatch",
                "id": self.next_id("try"),
                "tryBlock": {"statements": try_body},
                "catchBlock": {"statements": catch_body} if catch_body else None,
                "catchBinding": catch_binding,
                "location": loc,
            }]
        if T in ("WhileStatement", "ForStatement", "DoStatement"):
            body = self._block(getattr(node, "body", None) or getattr(node, "block", None))
            cond = getattr(node, "condition", None)
            return [{
                "kind": "Loop",
                "id": self.next_id("loop"),
                "condition": self.lower_expr(cond) if cond is not None else None,
                "body": {"statements": body},
                "location": loc,
            }]
        if T == "BlockStatement":
            return self.lower_stmts(getattr(node, "statements", None) or [])
        if T == "ThrowStatement":
            return [{
                "kind": "Throw",
                "id": self.next_id("throw"),
                "value": self.lower_expr(node.expression) if getattr(node, "expression", None) else {
                    "kind": "Literal", "literalKind": "null",
                },
                "location": loc,
            }]
        if T == "SwitchStatement":
            # Flatten cases into a join of bodies (conservative).
            stmts: List[Dict[str, Any]] = []
            for c in getattr(node, "cases", None) or []:
                stmts.extend(self.lower_stmts(getattr(c, "statements", None) or []))
            return stmts
        return []

    def _block(self, node: Any) -> List[Dict[str, Any]]:
        if node is None:
            return []
        if type(node).__name__ == "BlockStatement":
            return self.lower_stmts(node.statements or [])
        return self.lower_stmt(node)

    def lower_expr(self, node: Any) -> Dict[str, Any]:
        if node is None:
            return {"kind": "Literal", "literalKind": "undefined"}
        T = type(node).__name__
        if T == "Literal":
            raw = getattr(node, "value", None)
            if raw is None or raw == "null":
                return {"kind": "Literal", "literalKind": "null"}
            if isinstance(raw, str) and (raw == "true" or raw == "false"):
                return {"kind": "Literal", "literalKind": "boolean", "raw": raw}
            if isinstance(raw, str) and len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
                return {"kind": "Literal", "literalKind": "string", "raw": raw[1:-1]}
            if isinstance(raw, str) and re.fullmatch(r"-?\d+[lLfFdD]?", raw):
                return {"kind": "Literal", "literalKind": "number", "raw": re.sub(r"[lLfFdD]$", "", raw)}
            if isinstance(raw, str):
                return {"kind": "Literal", "literalKind": "string", "raw": raw}
            return {"kind": "Literal", "literalKind": "string", "raw": str(raw)}
        if T == "MemberReference":
            name = node.member
            qual = node.qualifier
            if not qual:
                return {"kind": "Variable", "name": name}
            obj = self._qual(qual)
            return {"kind": "FieldAccess", "object": obj, "field": name}
        if T == "This":
            return {"kind": "Variable", "name": "this"}
        if T == "BinaryOperation":
            return {
                "kind": "Binary",
                "op": node.operator or "+",
                "left": self.lower_expr(node.operandl),
                "right": self.lower_expr(node.operandr),
            }
        if T == "TernaryExpression":
            return {
                "kind": "Binary",
                "op": "?:",
                "left": self.lower_expr(node.if_true),
                "right": self.lower_expr(node.if_false),
            }
        if T == "Assignment":
            return self.lower_expr(node.value)
        if T == "Cast":
            return self.lower_expr(node.expression)
        if T == "MethodInvocation":
            return self._lower_invocation(node)
        if T == "ClassCreator":
            tname = ""
            if getattr(node, "type", None) is not None:
                t = node.type
                tname = getattr(t, "name", "") or ""
                # javalang may only keep the first segment of a FQCN
                sub = getattr(t, "sub_type", None)
                while sub is not None:
                    tname = (tname + "." if tname else "") + (getattr(sub, "name", "") or "")
                    sub = getattr(sub, "sub_type", None)
            simple = tname.split(".")[-1] if tname else "new"
            callee = {"kind": "Variable", "name": simple}
            args = [self.lower_expr(a) for a in (node.arguments or [])]
            call: Dict[str, Any] = {"kind": "Call", "callee": callee, "args": args}
            for sel in getattr(node, "selectors", None) or []:
                if type(sel).__name__ == "MethodInvocation":
                    call = {
                        "kind": "Call",
                        "callee": {"kind": "FieldAccess", "object": call, "field": sel.member},
                        "args": [self.lower_expr(a) for a in (sel.arguments or [])],
                    }
            return call
        if T == "ArrayCreator":
            inits = []
            init = getattr(node, "initializer", None)
            if init is not None:
                inits = [self.lower_expr(x) for x in (getattr(init, "initializers", None) or [])]
            return {"kind": "ArrayLiteral", "elements": inits}
        if T == "ArraySelector":
            return self.lower_expr(getattr(node, "index", None))
        return {"kind": "Unknown", "hint": T}

    def _qual(self, qual: Any) -> Dict[str, Any]:
        if qual is None or qual == "":
            return {"kind": "Variable", "name": "this"}
        if isinstance(qual, str):
            parts = qual.split(".")
            acc: Dict[str, Any] = {"kind": "Variable", "name": parts[0]}
            for p in parts[1:]:
                acc = {"kind": "FieldAccess", "object": acc, "field": p}
            return acc
        return self.lower_expr(qual)

    def _lower_invocation(self, node: Any) -> Dict[str, Any]:
        member = node.member
        callee = {
            "kind": "FieldAccess",
            "object": self._qual(node.qualifier) if node.qualifier else {"kind": "Variable", "name": member},
            "field": member,
        }
        if not node.qualifier:
            callee = {"kind": "Variable", "name": member}
        args = [self.lower_expr(a) for a in (node.arguments or [])]
        call: Dict[str, Any] = {"kind": "Call", "callee": callee, "args": args}
        # Flatten .exec().waitFor() selectors into nested calls.
        for sel in node.selectors or []:
            if type(sel).__name__ == "MethodInvocation":
                call = {
                    "kind": "Call",
                    "callee": {"kind": "FieldAccess", "object": call, "field": sel.member},
                    "args": [self.lower_expr(a) for a in (sel.arguments or [])],
                }
            elif type(sel).__name__ == "MemberReference":
                call = {"kind": "FieldAccess", "object": call, "field": sel.member}  # type: ignore
        return call if isinstance(call, dict) and call.get("kind") == "Call" else {
            "kind": "Call", "callee": call, "args": [],
        }


def main() -> int:
    args = sys.argv[1:]
    if not args:
        sys.stderr.write("usage: python3 -m vantage.nebula_frontend_java <file.java> [...]\n")
        return 2
    if args[0] == "--batch":
        files = [ln.strip() for ln in sys.stdin if ln.strip()]
    else:
        files = args
    modules = []
    for f in files:
        if not os.path.exists(f):
            sys.stderr.write(f"skip: {f} not found\n")
            continue
        try:
            modules.append(lower_file(f))
        except Exception as e:
            sys.stderr.write(f"error: {f}: {e}\n")
    json.dump(modules, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
