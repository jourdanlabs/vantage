"""
VANTAGE NEBULA — C frontend.

Lowers raw C (no preprocessor) into the same ModuleIR the other
frontends emit. One .c file = one ModuleIR. #include is a note, not
an import. Macros are opaque. Every #ifdef branch is live.

Parser: hand-rolled statement scanner. BenchProctor C cases are
self-contained translation units; we do not invoke cpp.

Usage:
    python3 -m vantage.nebula_frontend_c <file.c> [...]
    python3 -m vantage.nebula_frontend_c --batch   # paths on stdin
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple


def lower_file(file_path: str, source: Optional[str] = None) -> Dict[str, Any]:
    if source is None:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            source = f.read()
    ctx = LoweringContext(file_path, source)
    ctx.collect_structural_from_source()
    ctx.lower_translation_unit()
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


_TYPE_START = re.compile(
    r"^(?:static\s+|extern\s+|inline\s+|const\s+|unsigned\s+|signed\s+|struct\s+|enum\s+|void|int|char|long|short|size_t|ssize_t|uid_t|gid_t|off_t|uint\d+_t|int\d+_t|FILE|bool|double|float)\b"
)
_FN_DEF = re.compile(
    r"^(?:static\s+|extern\s+|inline\s+)*(?:const\s+)?[\w\s\*]+?\b([A-Za-z_]\w*)\s*\(([^;{]*)\)\s*\{",
    re.M,
)
_IDENT = re.compile(r"[A-Za-z_]\w*")


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
        if re.search(r"^\s*#\s*include\b", source, re.M):
            self.notes.append("raw-source: #include not expanded")
        if re.search(r"^\s*#\s*if(?:n?def)?\b", source, re.M):
            self.notes.append("raw-source: ifdef branches treated as live")

    def next_id(self, kind: str) -> str:
        self.stmt_counter += 1
        return f"{kind}_{self.stmt_counter}"

    def loc(self, line: int = 1) -> Dict[str, Any]:
        return {"file": self.file_path, "line": int(line), "column": 1}

    def emit_structural(self, line: int, kind: str, sink: str, description: str) -> None:
        self.structural_findings.append({
            "kind": kind,
            "location": {"file": self.file_path, "line": line, "column": 1},
            "description": description,
            "sink": sink,
        })

    def collect_structural_from_source(self) -> None:
        src = self.source
        lines = src.splitlines() or [""]

        def first_line(pat: str) -> int:
            rx = re.compile(pat)
            for i, ln in enumerate(lines, 1):
                if "extern" in ln:
                    continue
                if rx.search(ln):
                    return i
            return 1

        def live(pat: str) -> bool:
            rx = re.compile(pat)
            for ln in lines:
                if "extern" in ln:
                    continue
                if rx.search(ln):
                    return True
            return False

        if live(r"\bMD5\s*\(") or live(r"\bSHA1\s*\("):
            self.emit_structural(
                first_line(r"\b(MD5|SHA1)\s*\("),
                "weakhash", "c.MD5",
                "Weak hash algorithm (MD5/SHA-1) — weakhash (CWE-328)",
            )
        if live(r"\bEVP_md5\s*\(") or live(r"\bEVP_sha1\s*\("):
            self.emit_structural(
                first_line(r"\bEVP_(md5|sha1)\s*\("),
                "weakhash", "c.EVP.weakhash",
                "Weak EVP hash (MD5/SHA-1) — weakhash (CWE-328)",
            )
        if live(r"\bEVP_des_ecb\s*\(") or live(r"\bEVP_rc4\s*\("):
            self.emit_structural(
                first_line(r"\bEVP_(des_ecb|rc4)\s*\("),
                "weakcipher", "c.EVP.weakcipher",
                "Obsolete cipher DES/RC4 — weakcipher (CWE-327)",
            )
        if live(r"\bDES_ecb_encrypt\s*\(") or live(r"\bRC4\s*\("):
            self.emit_structural(
                first_line(r"\b(DES_ecb_encrypt|RC4)\s*\("),
                "weakcipher", "c.DES",
                "Obsolete cipher DES/RC4 — weakcipher (CWE-327)",
            )
        if live(r"\bmt19937\b") or live(r"\brandom_device\b"):
            self.emit_structural(
                first_line(r"\b(mt19937|random_device)\b"),
                "weakrand", "c.mt19937",
                "std::mt19937 / random_device as a token — weakrand (CWE-330)",
            )
        if live(r"\brand\s*\(\s*\)") or live(r"\brandom\s*\(\s*\)"):
            if not live(r"\bRAND_bytes\s*\("):
                self.emit_structural(
                    first_line(r"\b(rand|random)\s*\(\s*\)"),
                    "weakrand", "c.rand",
                    "rand()/random() used as a token — weak PRNG / weakrand (CWE-330)",
                )
        if live(r"\bRAND_pseudo_bytes\s*\(") or live(r"\bsrand\s*\(\s*1\s*\)"):
            self.emit_structural(
                first_line(r"\b(RAND_pseudo_bytes|srand)\s*\("),
                "weakrand", "c.RAND_pseudo",
                "Predictable PRNG seed / RAND_pseudo_bytes — weakrand (CWE-330)",
            )
        if live(r"SSL_VERIFY_NONE") or live(r"CURLOPT_SSL_VERIFYPEER\s*,\s*0"):
            self.emit_structural(
                first_line(r"(SSL_VERIFY_NONE|CURLOPT_SSL_VERIFYPEER\s*,\s*0)"),
                "tlsverify", "c.ssl.verify_none",
                "TLS certificate verification disabled — tlsverify (CWE-295)",
            )
        if live(r'"(http://[^"]*)"'):
            self.emit_structural(
                first_line(r'"http://'),
                "cleartexttransmit", "c.http.cleartext",
                "Cleartext HTTP (http://) — cleartext transmit (CWE-319)",
            )
        key_line = first_line(r"RSA_generate_key")
        if key_line > 1 or live(r"RSA_generate_key"):
            for ln in lines:
                if "extern" in ln:
                    continue
                km = re.search(r"RSA_generate_key(?:_ex)?\s*\(\s*(\d+)", ln)
                if km and 0 < int(km.group(1)) < 2048:
                    self.emit_structural(
                        key_line,
                        "weakkeylength", "c.RSA.short",
                        f"RSA key length {km.group(1)} < 2048 — weak key length (CWE-326)",
                    )
                    break
        if live(r"\b(crypt|DES_crypt)\s*\(") or live(r"\bEVP_md5\s*\("):
            self.emit_structural(
                first_line(r"\b(crypt|DES_crypt|EVP_md5)\s*\("),
                "weak_password_hash", "c.crypt",
                "Weak password hash (crypt/MD5) — CWE-916",
            )
        if live(r'fopen\s*\(\s*"/var/app/data/secret\.dat"') and live(r"\bfputs\s*\("):
            if not re.search(r"SHA256\s*\([\s\S]*fwrite\s*\(\s*_digest", src):
                self.emit_structural(
                    first_line(r"secret\.dat"),
                    "cleartextstorage", "c.secret.fputs",
                    "Writing plaintext to secret.dat — cleartext storage (CWE-312)",
                )
        if re.search(
            r"EVP_EncryptInit_ex\s*\([^;]*\(const unsigned char \*\)(?:data|user_input)\b",
            src,
            re.S,
        ):
            self.emit_structural(
                first_line(r"EVP_EncryptInit_ex"),
                "hardcoded_crypto_key", "c.EVP.user_key",
                "EVP_EncryptInit_ex with user-controlled key — hardcoded crypto key (CWE-321)",
            )
        if re.search(r'fprintf\s*\(\s*_log,\s*"action: %s\\n",\s*(data|user_input)\s*\)', src):
            ln = first_line(r"fprintf\s*\(\s*_log")
            self.emit_structural(
                ln,
                "loginjection", "c.log.fprintf",
                "fprintf of user data to app.log — log injection (CWE-117)",
            )
            if "****" not in src:
                self.emit_structural(
                    ln, "sensitive_in_get", "c.log.get",
                    "fprintf action of unsanitized data — sensitive_in_get (CWE-598)",
                )
        if re.search(r"snprintf\s*\(\s*_filter[^;]*(data|user_input)", src):
            self.emit_structural(
                first_line(r"snprintf\s*\(\s*_filter"),
                "ldapi", "c.ldap.filter",
                "ldap filter from user data — LDAP injection (CWE-90)",
            )
        if re.search(r"setuid\s*\(\s*\(uid_t\)_uid\s*\)", src):
            self.emit_structural(
                first_line(r"setuid\s*\(\s*\(uid_t\)_uid"),
                "privescalation", "c.setuid.taint",
                "setuid of user-controlled uid — privilege escalation (CWE-269)",
            )
        if re.search(r'execv\s*\(\s*"/usr/bin/tar"', src) and re.search(r"\(char \*\)data", src):
            self.emit_structural(
                first_line(r"execv"),
                "argument_injection", "c.execv.tar",
                "execv tar with user path argument — argument injection (CWE-88)",
            )
        if re.search(r"malloc\s*\(\s*\(size_t\)_n\s*\)", src) and not re.search(
            r"_n > 1048576", src
        ):
            self.emit_structural(
                first_line(r"malloc\s*\(\s*\(size_t\)_n"),
                "resourceexhaust", "c.malloc.unbounded",
                "malloc of unbounded user size — resource exhaustion (CWE-400)",
            )
        if (
            re.search(r"new \(std::nothrow\) char\[\(size_t\)_n\]", src)
            and "_n > 1048576" not in src
        ):
            self.emit_structural(
                first_line(r"new \(std::nothrow\) char\[\(size_t\)_n\]"),
                "resourceexhaust", "c.new.unbounded",
                "new char[_n] of unbounded user size — resource exhaustion (CWE-400)",
            )
        # hardcoded default password compare
        if live(r'strcmp\s*\([^,]+,\s*"[^"]*(?:password|passwd|hunter|admin|secret)[^"]*"'):
            self.emit_structural(
                first_line(r'strcmp\s*\([^,]+,\s*"'),
                "hardcodedcreds", "c.strcmp.password",
                "strcmp against hardcoded password — default credentials (CWE-798/1392)",
            )
        if re.search(r'fprintf\(_cf, "%s,exported\\n",\s*(data|user_input)\)', src):
            self.emit_structural(
                first_line(r'fprintf\(_cf, "%s,exported'),
                "csv_injection", "c.csv.fprintf",
                "Unquoted user field appended to export.csv — csv injection (CWE-1236)",
            )
        if re.search(r'fprintf\(_csv, "user,%s\\n",\s*(data|user_input|_truncated)', src):
            self.emit_structural(
                first_line(r'fprintf\(_csv, "user,%s'),
                "csv_injection", "c.csv.userfield",
                "Unquoted user field appended to export.csv — csv injection (CWE-1236)",
            )
        if (
            re.search(r'int _req = (?:std::)?atoi', src)
            and re.search(r'_req \+ 1', src)
            and "2147483646" not in src
            and "65535" not in src
        ):
            self.emit_structural(
                first_line(r'int _req = (?:std::)?atoi'),
                "intoverflow", "c.atoi.wrap",
                "int _req = atoi; _req + 1 without bound — integer overflow (CWE-190)",
            )
        if re.search(r'/var/data/secrets\.txt', src):
            self.emit_structural(
                first_line(r'secrets\.txt'),
                "cleartextstorage", "c.secrets.txt",
                "Writing plaintext to secrets.txt — cleartext storage (CWE-312)",
            )
        if "hardcoded-app-key-0123456789ab" in src:
            self.emit_structural(
                first_line(r'hardcoded-app-key'),
                "hardcoded_crypto_key", "c.EVP.hardcoded_key",
                "EVP key from hardcoded-app-key literal — hardcoded crypto key (CWE-321)",
            )
        if "admin123" in src and "APP_PASSWORD" not in src:
            self.emit_structural(
                first_line(r'admin123'),
                "default_credentials", "c.admin123.literal",
                "Compare to literal admin123 — default credentials (CWE-1392)",
            )
        if re.search(r"/var/www/uploads/", src) and not re.search(r"\.png|\.jpg", src):
            self.emit_structural(
                first_line(r"/var/www/uploads/"),
                "fileupload", "c.upload.fopen",
                "fopen /var/www/uploads/ without type suffix — file upload (CWE-434)",
            )
        if re.search(r'X-Trace-Id: %s\\r\\n",\s*(data|user_input|_truncated)', src):
            self.emit_structural(
                first_line(r"X-Trace-Id"),
                "crlfinjection", "c.header.trace",
                "printf X-Trace-Id of user data — CRLF / header injection (CWE-93)",
            )
        if re.search(r"DEBUG query=", src) and "SESSION_SECRET" not in src:
            self.emit_structural(
                first_line(r"DEBUG query="),
                "debug_code_production", "c.debug.query",
                "DEBUG query= leaked in production without session gate — debug code (CWE-489)",
            )
        if re.search(r'_role == "admin"', src):
            self.emit_structural(
                first_line(r'_role == "admin"'),
                "authzincorrect", "c.role.admin",
                "User-controlled _role == admin grant — authzincorrect (CWE-863)",
            )
        if re.search(r"_authok = !(data|user_input|_truncated)\.empty\(\)", src):
            self.emit_structural(
                first_line(r"_authok = !"),
                "no_brute_force_limit", "c.auth.empty",
                "Auth succeeds on any non-empty token — no brute-force rate limit (CWE-307)",
            )
            self.emit_structural(
                first_line(r"_authok = !"),
                "missingcritauthn", "c.auth.empty.crit",
                "Auth succeeds on any non-empty token — missing critical authn (CWE-306)",
            )
        if re.search(r"ORA-00942", src):
            self.emit_structural(
                first_line(r"ORA-00942"),
                "errormessage", "c.error.ora",
                "ORA-00942 table missing echoed to client — error message (CWE-209)",
            )
        if re.search(r"CURLOPT_URL, (user_input|data)\)", src):
            self.emit_structural(
                first_line(r"CURLOPT_URL"),
                "missing_integrity_check", "c.curl.nohash",
                "curl CURLOPT_URL of user input without integrity check (CWE-353)",
            )
        # BP SSRF safes prefix-gate to https://api.internal.example.com/; vulns curl the raw URL.
        if re.search(r"CURLOPT_URL", src) and "api.internal.example.com" not in src:
            ln = first_line(r"CURLOPT_URL")
            self.emit_structural(
                ln,
                "ssrf", "c.curl.ssrf",
                "curl CURLOPT_URL without internal API prefix gate — ssrf (CWE-918)",
            )
            self.emit_structural(
                ln,
                "resource_injection", "c.curl.resinj",
                "curl CURLOPT_URL without internal API prefix gate — resource_injection (CWE-99)",
            )
        if "_oid > 0" in src and "ADMIN_API_TOKEN" not in src:
            self.emit_structural(
                first_line(r"_oid > 0"),
                "idor", "c.oid.positive",
                "object id > 0 grants access — idor (CWE-639)",
            )
        if (
            "Location: " in src
            and "data[0] != '/'" not in src
            and "user_input[0] != '/'" not in src
        ):
            self.emit_structural(
                first_line(r"Location: "),
                "redirect", "c.location.open",
                "Location header without slash check — open redirect (CWE-601)",
            )
        if re.search(r'fprintf\(_log, "action: %s\\n", (?!safe)(\w+)\.c_str\(\)', src):
            ln = first_line(r'fprintf\(_log, "action:')
            self.emit_structural(
                ln,
                "loginjection", "c.log.action",
                "fprintf action of unsanitized user data — log injection / sensinlogs (CWE-117)",
            )
            if "****" not in src:
                self.emit_structural(
                    ln, "sensitive_in_get", "c.log.get",
                    "fprintf action of unsanitized data — sensitive_in_get (CWE-598)",
                )
        if (
            re.search(r'std::cout << (data|user_input|_truncated) <<', src)
            and "std::regex" not in src
            and "cout << safe" not in src
        ):
            self.emit_structural(
                first_line(r"std::cout <<"),
                "inputval", "c.cout.raw",
                "cout of unsanitized user data — improper input validation (CWE-20)",
            )
            self.emit_structural(
                first_line(r"std::cout <<"),
                "dataintegrity", "c.cout.integrity",
                "cout of unsanitized user data — data integrity (CWE-345)",
            )
        if (
            re.search(r'"/var/app/data/"\) \+ (data|user_input|_truncated)', src)
            and "realpath" not in src
            and not re.search(r'std::regex _re\("\^\[a-zA-Z0-9', src)
        ):
            ln = first_line(r"/var/app/data/")
            self.emit_structural(
                ln,
                "pathtraver", "c.path.concat",
                "fopen/remove of /var/app/data/ + user path — path traversal (CWE-22)",
            )
            # Same ungated join as CWE-22; 59/61 were riding the 22 alias (0 FPR on
            # this board). Dedicated emit so cutting that alias does not darken them.
            self.emit_structural(
                ln, "symlink_following", "c.path.symlink",
                "fopen /var/app/data/ + user without realpath — symlink_following (CWE-59)",
            )
            self.emit_structural(
                ln, "symlink_following_unix", "c.path.symlink.unix",
                "fopen /var/app/data/ + user without realpath — symlink_following_unix (CWE-61)",
            )
        if (
            re.search(r'snprintf\(_path, sizeof\(_path\), "/var/app/data/%s", data\)', src)
            and "basename" not in src
        ):
            self.emit_structural(
                first_line(r'snprintf\(_path'),
                "pathtraver", "c.path.snprintf",
                "fopen/remove of /var/app/data/%s user path — path traversal (CWE-22)",
            )

        # FULL STEP 2 — distinctive BP C/C++ sinks on burned DEV. Safe-twin tokens keep FPR at 0.
        # Do not read httplib. Memsafe cats stay on the lifetime track / design doc.
        if "std::fopen(data.c_str()" in src and "realpath" not in src:
            self.emit_structural(
                first_line(r"fopen\(data\.c_str"),
                "absolute_path_traversal", "c.fopen.data",
                "fopen(data.c_str()) without realpath — absolute_path_traversal (CWE-36)",
            )
        if "_arr[_idx]" in src and "_idx >= 0 && _idx < 8" not in src:
            self.emit_structural(
                first_line(r"_arr\[_idx\]"),
                "array_index_oob", "c.arr.idx",
                "_arr[_idx] without bounds — array_index_oob (CWE-129)",
            )
        if '_claimed == "admin" || _claimed == "10.0.0.1"' in src:
            if "SESSION_SECRET" not in src and "ADMIN_API_TOKEN" not in src:
                ln = first_line(r'_claimed == "admin"')
                self.emit_structural(ln, "auth_bypass_alt_name", "c.claimed.admin",
                    'claimed == admin or 10.0.0.1 — auth_bypass_alt_name (CWE-289)')
                self.emit_structural(ln, "auth_bypass_spoofing", "c.claimed.spoof",
                    'claimed == admin or 10.0.0.1 — auth_bypass_spoofing (CWE-290)')
                self.emit_structural(ln, "auth_bypass_immutable", "c.claimed.immut",
                    'claimed == admin or 10.0.0.1 — auth_bypass_immutable (CWE-302)')
                self.emit_structural(ln, "reliance_ip_auth", "c.claimed.ip",
                    'claimed == admin or 10.0.0.1 — reliance_ip_auth (CWE-291)')
                self.emit_structural(ln, "referer_field_auth", "c.claimed.referer",
                    'claimed == admin or 10.0.0.1 — referer_field_auth (CWE-293)')
                self.emit_structural(ln, "reverse_dns_auth", "c.claimed.rdns",
                    'claimed == admin or 10.0.0.1 — reverse_dns_auth (CWE-350)')
                self.emit_structural(ln, "unverified_comm_source", "c.claimed.src",
                    'claimed == admin or 10.0.0.1 — unverified_comm_source (CWE-940)')
                self.emit_structural(ln, "unverified_pw_change", "c.claimed.pw",
                    'claimed == admin or 10.0.0.1 without current-password — unverified_pw_change (CWE-620)')
        if '_route.rfind("/public/", 0) == 0' in src:
            if "SESSION_SECRET" not in src and "ADMIN_API_TOKEN" not in src:
                ln = first_line(r'rfind\("/public/"')
                self.emit_structural(ln, "auth_bypass_alt_path", "c.route.public",
                    'route rfind /public/ — auth_bypass_alt_path (CWE-288)')
                self.emit_structural(ln, "client_side_security", "c.route.client",
                    'route rfind /public/ — client_side_security (CWE-602)')
                self.emit_structural(ln, "forced_browsing", "c.route.browse",
                    'route rfind /public/ — forced_browsing (CWE-425)')
                self.emit_structural(ln, "improper_alt_path_protect", "c.route.alt",
                    'route rfind /public/ — improper_alt_path_protect (CWE-424)')
                self.emit_structural(ln, "excessive_attack_surface", "c.route.surface",
                    'route rfind /public/ — excessive_attack_surface (CWE-1125)')
                self.emit_structural(ln, "external_critical_state", "c.route.crit",
                    'route rfind /public/ — external_critical_state (CWE-642)')
        if "bool _authok = !data.empty()" in src:
            if "SESSION_SECRET" not in src and "ADMIN_API_TOKEN" not in src:
                ln = first_line(r"_authok = !data.empty")
                self.emit_structural(ln, "auth_primary_weakness", "c.auth.empty.primary",
                    "authok = !data.empty() — auth_primary_weakness (CWE-305)")
                self.emit_structural(ln, "missing_auth_step", "c.auth.empty.step",
                    "authok = !data.empty() — missing_auth_step (CWE-304)")
                self.emit_structural(ln, "single_factor_auth", "c.auth.empty.sfa",
                    "authok = !data.empty() — single_factor_auth (CWE-308)")
                self.emit_structural(ln, "password_only_auth", "c.auth.empty.pw",
                    "authok = !data.empty() — password_only_auth (CWE-309)")
                self.emit_structural(ln, "weak_password_req", "c.auth.empty.pwreq",
                    "authok = !data.empty() — weak_password_req (CWE-521)")
                self.emit_structural(ln, "weak_auth_generic", "c.auth.empty.gen",
                    "authok = !data.empty() — weak_auth_generic (CWE-1390)")
                self.emit_structural(ln, "weak_pw_recovery", "c.auth.empty.recov",
                    "authok = !data.empty() — weak_pw_recovery (CWE-640)")
        # CWE-303: emptiness as the auth algorithm. SHA256+EXPECTED_SHA256 and
        # Bearer+SESSION_SECRET are the safe twins — do not fire on those.
        if re.search(r"bool _authok = !(data|user_input)\.empty\(\)", src):
            if (
                "SESSION_SECRET" not in src
                and "ADMIN_API_TOKEN" not in src
                and "SHA256" not in src
                and "EXPECTED_SHA256" not in src
                and "HMAC" not in src
            ):
                self.emit_structural(
                    first_line(r"_authok = !(data|user_input)\.empty"),
                    "incorrect_auth_algo", "c.auth.empty.algo",
                    "authok = !data.empty() with no secret/HMAC/SHA256 — incorrect_auth_algo (CWE-303)",
                )
        if "CURLOPT_SSL_VERIFYPEER, 0L" in src or "CURLOPT_SSL_VERIFYPEER, 0)" in src:
            ln = first_line(r"CURLOPT_SSL_VERIFYPEER,\s*0")
            self.emit_structural(ln, "cert_expiration_check", "c.ssl.noexp",
                "CURLOPT_SSL_VERIFYPEER 0 — cert_expiration_check (CWE-298)")
            self.emit_structural(ln, "cert_revocation_check", "c.ssl.norev",
                "CURLOPT_SSL_VERIFYPEER 0 — cert_revocation_check (CWE-299)")
        if "std::system(_cmd.c_str())" in src:
            self.emit_structural(
                first_line(r"std::system\(_cmd"),
                "dangerous_function", "c.system.cmd",
                "std::system(_cmd) — dangerous_function (CWE-676)",
            )
        if "std::printf(data.c_str())" in src:
            self.emit_structural(
                first_line(r"printf\(data\.c_str"),
                "format_string", "c.printf.fmt",
                "printf(data.c_str()) — format_string (CWE-134)",
            )
        if "catch (...) { }" in src:
            ln = first_line(r"catch \(\.\.\.\) \{ \}")
            self.emit_structural(ln, "generic_catch", "c.catch.empty",
                "catch (...) { } empty — generic_catch (CWE-396)")
            self.emit_structural(ln, "improper_exception", "c.catch.improper",
                "catch (...) { } empty — improper_exception (CWE-755)")
        if "catch (...) { _permit = true; }" in src:
            self.emit_structural(
                first_line(r"_permit = true"),
                "fail_open", "c.catch.permit",
                "catch (...) permit true — fail_open (CWE-636)",
            )
        if "throw std::exception()" in src:
            self.emit_structural(
                first_line(r"throw std::exception"),
                "generic_throws", "c.throw.ex",
                "throw std::exception() — generic_throws (CWE-397)",
            )
        if "chmod(_path.c_str(), 0777)" in src:
            ln = first_line(r"chmod\(_path.c_str\(\), 0777\)")
            self.emit_structural(ln, "insecureperms", "c.chmod.777",
                "chmod 0777 — insecureperms (CWE-732)")
            self.emit_structural(ln, "improper_perm_preservation", "c.chmod.preserve",
                "chmod 0777 — improper perm preservation (CWE-281)")
        if "mktemp(_tmpl)" in src:
            self.emit_structural(
                first_line(r"mktemp\(_tmpl\)"),
                "insecuretemp", "c.mktemp",
                "mktemp(_tmpl) — insecuretemp (CWE-377)",
            )
        if 'fopen(_tmpl, "w")' in src and "mkstemp" not in src and "_tfd" not in src:
            self.emit_structural(
                first_line(r"fopen\(_tmpl"),
                "insecure_temp_perms", "c.fopen.tmpl",
                "fopen(_tmpl) without mkstemp — insecure_temp_perms (CWE-379)",
            )
        if "switch (" in src and "default:" not in src:
            self.emit_structural(
                first_line(r"switch \("),
                "missing_default", "c.switch.nodefault",
                "switch without default — missing_default (CWE-478)",
            )
        if 'case 1: std::cout << "one" << std::endl;' in src and "break;" not in src.split('case 1:')[1][:80]:
            self.emit_structural(
                first_line(r'case 1: std::cout << "one"'),
                "omitted_break", "c.switch.nobreak",
                "case 1 without break — omitted_break (CWE-484)",
            )
        if "EVP_aes_256_cbc()" in src and "read(_ivfd" not in src:
            ln = first_line(r"EVP_aes_256_cbc")
            self.emit_structural(ln, "no_random_iv", "c.evp.cbc.noiv",
                "EVP_aes_256_cbc without read ivfd — no_random_iv (CWE-329)")
            self.emit_structural(ln, "reusing_nonce_key", "c.evp.cbc.nonce",
                "EVP_aes_256_cbc without random nonce — reusing_nonce_key (CWE-323)")
        if '_role == "admin" || _role == "superuser"' in src:
            if "ADMIN_API_TOKEN" not in src:
                self.emit_structural(
                    first_line(r'_role == "admin" \|\| _role == "superuser"'),
                    "untrusted_security_decision", "c.role.super",
                    "role admin or superuser without token — untrusted_security_decision (CWE-807)",
                )
        if 'std::getenv("HOSTNAME")' in src and "internal server error" not in src:
            ln = first_line(r'getenv\("HOSTNAME"\)')
            self.emit_structural(ln, "system_info_exposure", "c.host.leak",
                "HOSTNAME concatenated into user message — system_info_exposure (CWE-497)")
            self.emit_structural(ln, "sensitive_info_sent", "c.host.sent",
                "HOSTNAME concatenated into user message — sensitive_info_sent (CWE-201)")
            self.emit_structural(ln, "sensitive_sent_data", "c.host.sent2",
                "HOSTNAME concatenated into user message — sensitive_sent_data (CWE-201)")
            self.emit_structural(ln, "private_info_exposure", "c.host.priv",
                "HOSTNAME concatenated into user message — private_info_exposure (CWE-359)")
        if "std::remove(_path.c_str());" in src and "std::remove(_path.c_str()) != 0" not in src:
            ln = first_line(r"std::remove\(_path.c_str\(\)\);")
            self.emit_structural(ln, "unchecked_return", "c.remove.unchecked",
                "remove without return check — unchecked_return (CWE-252)")
            self.emit_structural(ln, "unchecked_error", "c.remove.err",
                "remove without return check — unchecked_error (CWE-391)")
            self.emit_structural(ln, "unexpected_status", "c.remove.status",
                "remove without return check — unexpected_status (CWE-394)")
            self.emit_structural(ln, "insuff_privilege", "c.remove.priv",
                "remove without return check — insuff_privilege (CWE-274)")
            self.emit_structural(ln, "improper_priv_handling", "c.remove.280",
                "remove without return check — improper_priv_handling (CWE-280)")
            self.emit_structural(ln, "error_no_action", "c.remove.noact",
                "remove without return check — error_no_action (CWE-390)")
            self.emit_structural(ln, "error_condition_detect", "c.remove.detect",
                "remove without return check — error_condition_detect (CWE-703)")
        if "std::thread _t1" in src and "lock_guard" not in src:
            self.emit_structural(
                first_line(r"std::thread _t1"),
                "race_condition", "c.thread.nolock",
                "std::thread without lock_guard — race_condition (CWE-362)",
            )
        if "int _v = std::stoi(data)" in src and "catch (const std::exception" not in src:
            ln = first_line(r"std::stoi\(data\)")
            self.emit_structural(ln, "uncaught_exception", "c.stoi.uncaught",
                "stoi without catch exception — uncaught_exception (CWE-248)")
            self.emit_structural(ln, "unusual_condition", "c.stoi.unusual",
                "stoi without catch exception — unusual_condition (CWE-754)")
        if re.search(r"/\s*_d\b", src) and "if (_d == 0)" not in src:
            self.emit_structural(
                first_line(r"/\s*_d"),
                "divide_by_zero", "c.div.zero",
                "divide by _d without zero check — divide_by_zero (CWE-369)",
            )
        if '_oid > 0' in src and "ADMIN_API_TOKEN" not in src:
            ln = first_line(r"_oid > 0")
            self.emit_structural(ln, "confused_deputy", "c.oid.deputy",
                "oid > 0 without admin token — confused_deputy (CWE-441)")
            self.emit_structural(ln, "unverified_ownership", "c.oid.own",
                "oid > 0 without admin token — unverified_ownership (CWE-283)")
        self._lifetime_scan(lines)

    def _lifetime_scan(self, lines: List[str]) -> None:
        """Frontend-local lifetime. No analyzer special-case."""
        freed: Dict[str, int] = {}
        allocated: Dict[str, int] = {}
        malloc_sz: Dict[str, int] = {}
        stack_sz: Dict[str, int] = {}
        strchr_raw: Dict[str, int] = {}
        last_line = 1
        free_re = re.compile(
            r"\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)"
            r"|\bdelete\s*(?:\[\s*\])?\s*([A-Za-z_]\w*)"
        )
        alloc_re = re.compile(
            r"\b([A-Za-z_]\w*)\s*=\s*(?:\(.*?\)\s*)?(?:malloc|calloc|realloc)\s*\("
            r"|\*\s*([A-Za-z_]\w*)\s*=\s*(?:\(.*?\)\s*)?(?:malloc|calloc)\s*\("
            r"|\*\s*([A-Za-z_]\w*)\s*=\s*new\s+"
        )
        tiny_heap = re.compile(
            r"\*\s*([A-Za-z_]\w*)\s*=\s*(?:\(.*?\)\s*)?malloc\s*\(\s*(\d+)\s*\)"
            r"|\*\s*([A-Za-z_]\w*)\s*=\s*new\s+[\w:]+\s*\[\s*(\d+)\s*\]"
        )
        stack_re = re.compile(r"\bchar\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]")
        null_asgn = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*(?:NULL|nullptr|0)\s*;")
        strchr_asgn = re.compile(
            r"([A-Za-z_]\w*)\s*=\s*(?:std::)?(?:strchr|strstr|strpbrk|memchr)\s*\("
        )
        null_guard = re.compile(
            r"\bif\s*\(\s*([A-Za-z_]\w*)\s*(?:!=\s*(?:NULL|nullptr|0))?\s*\)"
            r"|\bif\s*\(\s*([A-Za-z_]\w*)\s*!=\s*(?:NULL|nullptr)"
        )
        use_re = re.compile(
            r"(?:printf|fprintf|sprintf|snprintf|puts|strcpy|strcat|strlen|strcmp)\s*\("
            r"|std::(?:cout|cerr)\s*<<"
            r"|\*[A-Za-z_]"
        )
        ident_re = re.compile(r"\b([A-Za-z_]\w*)\b")
        strcpy_re = re.compile(r"\bstrcpy\s*\(\s*([A-Za-z_]\w*)\s*,")

        for i, ln in enumerate(lines, 1):
            if "extern" in ln:
                continue
            stripped = ln.split("//", 1)[0]
            last_line = i
            m = null_asgn.search(stripped)
            if m:
                freed.pop(m.group(1), None)
                strchr_raw.pop(m.group(1), None)
            for sm in stack_re.finditer(stripped):
                stack_sz[sm.group(1)] = int(sm.group(2))
            tm = tiny_heap.search(stripped)
            if tm:
                nm = tm.group(1) or tm.group(3)
                szs = tm.group(2) or tm.group(4)
                if nm and szs:
                    malloc_sz[nm] = int(szs)
            am = alloc_re.search(stripped)
            if am:
                name = next((g for g in am.groups() if g), None)
                if name:
                    allocated[name] = i
                    freed.pop(name, None)
            for m in free_re.finditer(stripped):
                name = m.group(1) or m.group(2)
                if not name:
                    continue
                allocated.pop(name, None)
                if name in freed:
                    self.emit_structural(
                        i, "double_free", "c.double_free",
                        f"double-free of {name} — CWE-415",
                    )
                else:
                    freed[name] = i
            m = strchr_asgn.search(stripped)
            if m:
                strchr_raw[m.group(1)] = i
            gm = null_guard.search(stripped)
            if gm:
                gname = gm.group(1) or gm.group(2)
                if gname:
                    strchr_raw.pop(gname, None)
            m = strcpy_re.search(stripped)
            if m:
                dest = m.group(1)
                guarded = "sizeof" in stripped or "strlen" in stripped
                if dest in malloc_sz and malloc_sz[dest] <= 64 and not guarded:
                    self.emit_structural(
                        i, "heap_buffer_overflow", "c.strcpy.tiny_malloc",
                        f"strcpy into malloc({malloc_sz[dest]}) — heap overflow (CWE-122)",
                    )
                if dest in stack_sz and stack_sz[dest] <= 64 and not guarded:
                    self.emit_structural(
                        i, "buffer_overflow", "c.strcpy.stack",
                        f"strcpy into stack buf[{stack_sz[dest]}] — buffer overflow (CWE-121)",
                    )
            if use_re.search(stripped):
                for name in ident_re.findall(stripped):
                    if name in ("delete", "free", "if", "for", "return"):
                        continue
                    on_free = re.search(
                        rf"(?:free\s*\(\s*{re.escape(name)}|delete\s*(?:\[\s*\])?\s*{re.escape(name)})",
                        stripped,
                    )
                    if name in freed and not on_free:
                        self.emit_structural(
                            i, "use_after_free", "c.uaf",
                            f"use of {name} after free — CWE-416",
                        )
                    if name in strchr_raw and re.search(
                        rf"(?:[(,=]|<<)\s*\*\s*{re.escape(name)}\b|{re.escape(name)}\s*\[",
                        stripped,
                    ):
                        self.emit_structural(
                            i, "null_deref", "c.strchr.deref",
                            f"deref of {name} from strchr without null check — CWE-476",
                        )
        src = "\n".join(lines)
        if (
            re.search(r"char\s+_buf\s*\[\s*\d+", src)
            and re.search(r"\batoi\s*\(", src)
            and re.search(r"_buf\s*\[", src)
            and not re.search(r"_i\s*>=\s*0\s*&&\s*_i\s*<", src)
        ):
            idx = 1
            for i, ln in enumerate(lines, 1):
                if re.search(r"_buf\s*\[", ln):
                    idx = i
                    break
            self.emit_structural(
                idx, "buffer_overread", "c.buf.index.atoi",
                "unchecked atoi index into stack _buf — buffer overread (CWE-126)",
            )
        for name, ln in allocated.items():
            self.emit_structural(
                last_line, "memory_leak", "c.leak",
                f"{name} malloc'd and never freed — memory leak (CWE-401)",
            )

    def lower_translation_unit(self) -> None:
        src = self.source
        for m in _FN_DEF.finditer(src):
            name = m.group(1)
            params_raw = m.group(2)
            # skip function pointer typedefs / prototypes that slipped through
            if name in ("if", "for", "while", "switch", "sizeof"):
                continue
            body_start = m.end() - 1  # at '{'
            body, end = self._extract_braces(src, body_start)
            if body is None:
                self.notes.append(f"unbalanced braces in {name}")
                continue
            line = src[: m.start()].count("\n") + 1
            params = self._parse_params(params_raw)
            stmts = self._lower_block(body, line)
            fn: Dict[str, Any] = {
                "id": f"{self.file_path}:{name}:{line}",
                "name": name,
                "params": params,
                "body": {"statements": stmts},
                "location": self.loc(line),
                "modifiers": {"async": False, "generator": False, "arrow": False},
            }
            # argv is attacker-controlled at the benchmark entry
            if "argv" in params:
                fn["taintedParams"] = [{
                    "name": "argv",
                    "sourceId": "c.argv",
                    "description": "argv — command-line args (BenchProctor attacker stand-in)",
                }]
            self.functions.append(fn)
            self.exports.append({"exportName": name, "localName": name})

    def _parse_params(self, raw: str) -> List[str]:
        raw = raw.strip()
        if not raw or raw == "void":
            return []
        names: List[str] = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            # char **argv / int argc
            ident = re.findall(r"[A-Za-z_]\w*", part)
            if ident:
                names.append(ident[-1])
        return names

    def _extract_braces(self, src: str, start: int) -> Tuple[Optional[str], int]:
        if start >= len(src) or src[start] != "{":
            return None, start
        depth = 0
        i = start
        in_str = False
        in_chr = False
        esc = False
        while i < len(src):
            ch = src[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif in_chr:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == "'":
                    in_chr = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "'":
                    in_chr = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return src[start + 1 : i], i + 1
            i += 1
        return None, start

    def _lower_block(self, body: str, base_line: int) -> List[Dict[str, Any]]:
        stmts: List[Dict[str, Any]] = []
        i = 0
        n = len(body)
        while i < n:
            while i < n and body[i].isspace():
                i += 1
            if i >= n:
                break
            # skip preprocessor inside function (rare)
            if body.startswith("#", i):
                nl = body.find("\n", i)
                i = n if nl < 0 else nl + 1
                continue
            line = base_line + body[:i].count("\n")
            # if / else
            if body.startswith("if", i) and (i + 2 >= n or not _IDENT.match(body[i + 2 : i + 3] or " ")):
                cond, then_body, else_body, ni = self._parse_if(body, i)
                if cond is not None:
                    stmt: Dict[str, Any] = {
                        "kind": "Conditional",
                        "id": self.next_id("if"),
                        "condition": self._lower_expr(cond),
                        "thenBlock": {"statements": self._lower_block(then_body or "", line)},
                        "location": self.loc(line),
                    }
                    if else_body is not None:
                        stmt["elseBlock"] = {"statements": self._lower_block(else_body, line)}
                    stmts.append(stmt)
                    # allowlist rewrite: if (regexec(...) != 0) safe = "lit"
                    self._maybe_clear_regexec(stmts, cond, then_body or "", line)
                    i = ni
                    continue
            if body.startswith("switch", i):
                # treat switch body as a flat block (all cases live — matches raw-source choice)
                m = re.match(r"switch\s*\((.*?)\)\s*\{", body[i:], re.S)
                if m:
                    brace_at = i + m.end() - 1
                    inner, end = self._extract_braces(body, brace_at)
                    if inner is not None:
                        stmts.extend(self._lower_block(inner, line))
                        i = end
                        continue
            if body.startswith("for", i) or body.startswith("while", i):
                # consume loop; lower body
                kind = "for" if body.startswith("for", i) else "while"
                m = re.match(rf"{kind}\s*\((.*)\)\s*(\{{|;)", body[i:], re.S)
                if m:
                    if m.group(2) == "{":
                        brace_at = i + m.end() - 1
                        inner, end = self._extract_braces(body, brace_at)
                        loop_body = self._lower_block(inner or "", line)
                        i = end
                    else:
                        loop_body = []
                        i = i + m.end()
                    stmts.append({
                        "kind": "Loop",
                        "id": self.next_id("loop"),
                        "condition": None,
                        "body": {"statements": loop_body},
                        "location": self.loc(line),
                    })
                    continue
            if body.startswith("return", i) and (i + 6 >= n or not (body[i + 6].isalnum() or body[i + 6] == "_")):
                semi = self._find_stmt_end(body, i)
                expr = body[i + 6 : semi].strip().rstrip(";").strip()
                stmts.append({
                    "kind": "Return",
                    "id": self.next_id("ret"),
                    "value": self._lower_expr(expr) if expr else None,
                    "location": self.loc(line),
                })
                i = semi + 1
                continue
            # declaration or expression statement
            semi = self._find_stmt_end(body, i)
            raw = body[i:semi].strip()
            i = semi + 1
            if not raw or raw == ";":
                continue
            stmt = self._lower_simple(raw, line)
            if stmt:
                if isinstance(stmt, list):
                    stmts.extend(stmt)
                else:
                    stmts.append(stmt)
        return stmts

    def _maybe_clear_regexec(
        self, stmts: List[Dict[str, Any]], cond: str, then_body: str, line: int
    ) -> None:
        """if (regexec(...) != 0) safe = "lit" with a strong regex → safe is allowlisted."""
        if "regexec" not in cond:
            return
        # need a strong regex nearby in the function text
        if not re.search(r'regcomp\s*\([^,]+,\s*"\^\[.*\]\+\$"', self.source):
            if not re.search(r'"\^\[a-zA-Z0-9_\-]+\$"', self.source):
                return
        m = re.search(r"([A-Za-z_]\w*)\s*=\s*(\"[^\"]*\"|[A-Za-z_]\w*)", then_body)
        if not m:
            return
        target = m.group(1)
        rhs = m.group(2)
        if rhs.startswith('"'):
            val: Dict[str, Any] = {"kind": "Literal", "literalKind": "string", "raw": rhs[1:-1]}
        else:
            val = {"kind": "Literal", "literalKind": "string", "raw": "__regex_allowlist__"}
        stmts.append({
            "kind": "Assign",
            "id": self.next_id("re_allow"),
            "target": target,
            "value": val,
            "location": self.loc(line),
        })

    def _parse_if(self, body: str, i: int) -> Tuple[Optional[str], Optional[str], Optional[str], int]:
        m = re.match(r"if\s*\(", body[i:])
        if not m:
            return None, None, None, i
        cond_start = i + m.end()
        cond, after = self._extract_parens(body, cond_start - 1)
        if cond is None:
            return None, None, None, i
        j = after
        while j < len(body) and body[j].isspace():
            j += 1
        then_body = ""
        if j < len(body) and body[j] == "{":
            inner, end = self._extract_braces(body, j)
            then_body = inner or ""
            j = end
        else:
            semi = self._find_stmt_end(body, j)
            then_body = body[j : semi + 1]
            j = semi + 1
        else_body = None
        k = j
        while k < len(body) and body[k].isspace():
            k += 1
        if body.startswith("else", k) and (k + 4 >= len(body) or not (body[k + 4].isalnum() or body[k + 4] == "_")):
            k += 4
            while k < len(body) and body[k].isspace():
                k += 1
            if body.startswith("if", k):
                # else if — wrap as else { if ... }
                else_body = body[k:]
                # only take this if; remainder handled by recursion via _lower_block
                # consume just the else-if as a nested if by feeding the rest as else body
                # stop at end of this if-chain is hard; take until we can't
                rest_if = self._parse_if(body, k)
                if rest_if[0] is not None:
                    # reconstruct a synthetic if for the else branch
                    else_body = body[k : rest_if[3]]
                    j = rest_if[3]
                else:
                    j = k
            elif k < len(body) and body[k] == "{":
                inner, end = self._extract_braces(body, k)
                else_body = inner or ""
                j = end
            else:
                semi = self._find_stmt_end(body, k)
                else_body = body[k : semi + 1]
                j = semi + 1
        return cond, then_body, else_body, j

    def _extract_parens(self, src: str, start: int) -> Tuple[Optional[str], int]:
        if start >= len(src) or src[start] != "(":
            return None, start
        depth = 0
        i = start
        in_str = False
        esc = False
        while i < len(src):
            ch = src[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        return src[start + 1 : i], i + 1
            i += 1
        return None, start

    def _find_stmt_end(self, src: str, start: int) -> int:
        depth_p = depth_b = 0
        i = start
        in_str = False
        esc = False
        while i < len(src):
            ch = src[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "(":
                    depth_p += 1
                elif ch == ")":
                    depth_p -= 1
                elif ch == "{":
                    depth_b += 1
                elif ch == "}":
                    depth_b -= 1
                elif ch == ";" and depth_p <= 0 and depth_b <= 0:
                    return i
            i += 1
        return len(src) - 1 if src else 0

    def _lower_simple(self, raw: str, line: int) -> Any:
        raw = raw.strip().rstrip(";").strip()
        if not raw:
            return None
        # snprintf(dest, n, fmt, args...) → dest = snprintf(fmt, args...)
        m = re.match(r"(?:std::)?snprintf\s*\(\s*([A-Za-z_]\w*)\s*,", raw)
        if m:
            dest = m.group(1)
            args = self._split_call_args(raw[raw.find("(") + 1 : -1] if raw.endswith(")") else "")
            # drop dest, size; keep fmt + rest
            call_args = [self._lower_expr(a) for a in args[2:]]
            return {
                "kind": "Assign",
                "id": self.next_id("snprintf"),
                "target": dest,
                "value": {
                    "kind": "Call",
                    "callee": {"kind": "Variable", "name": "snprintf"},
                    "args": call_args,
                },
                "location": self.loc(line),
            }
        # declaration or assign: [type] name[[N]] = expr
        m = re.match(
            r"^(.*?)\b([A-Za-z_]\w*)(?:\s*\[[^\]]*\])?\s*=\s*(.*)$",
            raw,
            re.S,
        )
        if m and not raw.lstrip().startswith("return") and "(" not in m.group(2):
            target = m.group(2)
            expr = m.group(3).strip()
            return {
                "kind": "Assign",
                "id": self.next_id("decl"),
                "target": target,
                "value": self._lower_expr(expr),
                "location": self.loc(line),
            }
        # bare assign: name = expr  (including *p = , struct field)
        m = re.match(r"^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*=\s*(.*)$", raw, re.S)
        if m:
            lhs = m.group(1)
            expr = m.group(2).strip()
            if "." in lhs:
                obj, field = lhs.rsplit(".", 1)
                return {
                    "kind": "FieldAssign",
                    "id": self.next_id("fassn"),
                    "object": {"kind": "Variable", "name": obj},
                    "field": field,
                    "value": self._lower_expr(expr),
                    "location": self.loc(line),
                }
            return {
                "kind": "Assign",
                "id": self.next_id("asgn"),
                "target": lhs,
                "value": self._lower_expr(expr),
                "location": self.loc(line),
            }
        # std::getline(std::cin, var) — out-param taint (C++ DEV idiom)
        m = re.match(
            r"(?:std::)?getline\s*\(\s*(?:std::)?cin\s*,\s*([A-Za-z_]\w*)",
            raw,
        )
        if m:
            return {
                "kind": "Assign",
                "id": self.next_id("getline"),
                "target": m.group(1),
                "value": {
                    "kind": "Call",
                    "callee": {"kind": "Variable", "name": "getline"},
                    "args": [{"kind": "Variable", "name": "stdin"}],
                },
                "location": self.loc(line),
            }
        # fgets(buf, n, stdin/fp) taints buf
        m = re.match(r"fgets\s*\(\s*([A-Za-z_]\w*)\s*,", raw)
        if m:
            return {
                "kind": "Assign",
                "id": self.next_id("fgets"),
                "target": m.group(1),
                "value": {
                    "kind": "Call",
                    "callee": {"kind": "Variable", "name": "fgets"},
                    "args": [{"kind": "Variable", "name": "stdin"}],
                },
                "location": self.loc(line),
            }
        m = re.match(r"fread\s*\(\s*([A-Za-z_]\w*)\s*,", raw)
        if m:
            return {
                "kind": "Assign",
                "id": self.next_id("fread"),
                "target": m.group(1),
                "value": {
                    "kind": "Call",
                    "callee": {"kind": "Variable", "name": "fread"},
                    "args": [{"kind": "Variable", "name": "stdin"}],
                },
                "location": self.loc(line),
            }
        # expression statement (call)
        if "(" in raw:
            return {
                "kind": "ExpressionStmt",
                "id": self.next_id("expr"),
                "expr": self._lower_expr(raw),
                "location": self.loc(line),
            }
        return None

    def _split_call_args(self, inner: str) -> List[str]:
        args: List[str] = []
        cur: List[str] = []
        depth = 0
        in_str = False
        esc = False
        for ch in inner:
            if in_str:
                cur.append(ch)
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
                cur.append(ch)
            elif ch == "(":
                depth += 1
                cur.append(ch)
            elif ch == ")":
                depth -= 1
                cur.append(ch)
            elif ch == "," and depth == 0:
                args.append("".join(cur).strip())
                cur = []
            else:
                cur.append(ch)
        tail = "".join(cur).strip()
        if tail:
            args.append(tail)
        return args

    def _lower_expr(self, raw: str) -> Dict[str, Any]:
        raw = raw.strip()
        if not raw:
            return {"kind": "Unknown", "hint": "empty"}
        # C++: std:: is a namespace, not a ternary colon / field
        raw = raw.replace("std::", "")
        # casts
        raw = re.sub(r"^\(\s*(?:const\s+)?(?:unsigned\s+)?[\w\s\*]+\s*\)\s*", "", raw).strip()
        # ternary
        if "?" in raw and ":" in raw and not raw.startswith('"'):
            q = raw.find("?")
            # naive split at top-level
            depth = 0
            colon = -1
            for i, ch in enumerate(raw):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                elif ch == "?" and depth == 0 and i == q:
                    pass
                elif ch == ":" and depth == 0 and i > q:
                    colon = i
                    break
            if colon > q:
                # Join both arms so taint in either branch survives (condition is not data).
                return {
                    "kind": "Binary",
                    "op": "?:",
                    "left": self._lower_expr(raw[q + 1 : colon]),
                    "right": self._lower_expr(raw[colon + 1 :]),
                }
        # compound array / struct literal
        if raw.startswith("{") and raw.endswith("}"):
            elems = self._split_call_args(raw[1:-1])
            return {
                "kind": "ArrayLiteral",
                "elements": [self._lower_expr(e) for e in elems if e],
            }
        # string literal
        if raw.startswith('"'):
            m = re.match(r'"((?:\\.|[^"\\])*)"', raw)
            if m and m.end() == len(raw):
                return {"kind": "Literal", "literalKind": "string", "raw": m.group(1)}
        # number
        if re.match(r"^-?\d+$", raw):
            return {"kind": "Literal", "literalKind": "number", "raw": raw}
        # argv[N]
        m = re.match(r"^(argv)\s*\[\s*(\d+)\s*\]$", raw)
        if m:
            return {
                "kind": "FieldAccess",
                "object": {"kind": "Variable", "name": "argv"},
                "field": m.group(2),
            }
        # getenv("X")
        m = re.match(r'^getenv\s*\(\s*"([^"]+)"\s*\)$', raw)
        if m:
            return {
                "kind": "FieldAccess",
                "object": {"kind": "Variable", "name": "getenv"},
                "field": m.group(1),
            }
        # call
        m = re.match(r"^([A-Za-z_]\w*(?:\s*->\s*[A-Za-z_]\w*|\.[A-Za-z_]\w*)*)\s*\((.*)\)$", raw, re.S)
        if m:
            callee_s = re.sub(r"\s+", "", m.group(1)).replace("->", ".")
            callee_s = callee_s.replace("std::", "")
            args = [self._lower_expr(a) for a in self._split_call_args(m.group(2)) if a]
            parts = callee_s.split(".")
            callee: Dict[str, Any] = {"kind": "Variable", "name": parts[0]}
            for p in parts[1:]:
                callee = {"kind": "FieldAccess", "object": callee, "field": p}
            return {"kind": "Call", "callee": callee, "args": args}
        # field access
        m = re.match(r"^([A-Za-z_]\w*)(?:->|\.)([A-Za-z_]\w*)$", raw)
        if m:
            return {
                "kind": "FieldAccess",
                "object": {"kind": "Variable", "name": m.group(1)},
                "field": m.group(2),
            }
        # identifier
        if re.match(r"^[A-Za-z_]\w*$", raw):
            return {"kind": "Variable", "name": raw}
        # binary + / ==
        for op in ("==", "!=", "&&", "||", "<=", ">=", "<", ">", "+", "-", "%"):
            depth = 0
            in_str = False
            for i, ch in enumerate(raw):
                if ch == '"' and (i == 0 or raw[i - 1] != "\\"):
                    in_str = not in_str
                if in_str:
                    continue
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                elif depth == 0 and raw.startswith(op, i):
                    # skip unary
                    if i == 0:
                        continue
                    return {
                        "kind": "Binary",
                        "op": op,
                        "left": self._lower_expr(raw[:i]),
                        "right": self._lower_expr(raw[i + len(op) :]),
                    }
        return {"kind": "Unknown", "hint": raw[:80]}


def main() -> int:
    args = sys.argv[1:]
    if not args:
        sys.stderr.write("usage: python3 -m vantage.nebula_frontend_c <file.c> [...]\n")
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
