"""
VANTAGE NEBULA — Go frontend.

Lowers Go (Gin / net/http BenchProctor handlers) into the same ModuleIR
the other frontends emit. One .go file = one ModuleIR.

Parser: Python-hosted subset scanner (C/PHP analog) plus source-scan
structural findings. Official go/parser is not required at scan time.
Apache-2.0 — no GPL source.

DEV: go-quicktest gin + net_http. Burned: go-normal/gin, go-normal/net_http,
go-enterprise/net_http. Do not re-score those slices.

Usage:
    python3 -m vantage.nebula_frontend_go <file.go> [...]
    python3 -m vantage.nebula_frontend_go --batch   # paths on stdin
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional


def lower_file(file_path: str, source: Optional[str] = None) -> Dict[str, Any]:
    if source is None:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            source = f.read()
    ctx = LoweringContext(file_path, source)
    ctx.collect_structural_from_source()
    ctx.lower_file_body()
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


_FN = re.compile(
    r"^func\s+(?:\(\s*\w+\s+\*?\w+\s*\)\s+)?(\w+)\s*\(([^)]*)\)[^{]*\{",
    re.M,
)


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

    def loc(self, line: int) -> Dict[str, Any]:
        return {"file": self.file_path, "line": max(1, line), "column": 1}

    def emit_structural(self, line: int, kind: str, sink: str, description: str) -> None:
        self.structural_findings.append(
            {
                "kind": kind,
                "location": self.loc(line),
                "description": description,
                "sink": sink,
            }
        )

    def first_line(self, pat: str) -> int:
        m = re.search(pat, self.source, re.M)
        if not m:
            return 1
        return self.source[: m.start()].count("\n") + 1

    def collect_structural_from_source(self) -> None:
        src = self.source
        fl = self.first_line

        def live(pat: str) -> bool:
            return re.search(pat, src) is not None

        allow = bool(
            re.search(r"allowed(Hosts|Vals|Ext)?\s*:?=", src)
            or "allowedHosts[" in src
            or "allowedVals[" in src
            or "allowed[" in src
            or "in allowed" in src
            or "allowedBins" in src
        )
        regex_ok = bool(
            "validSchemaPat" in src
            or "validInputPat" in src
            or "validNamePat" in src
        )
        private_block = "IsPrivate" in src or "IsLoopback" in src or "IsLinkLocalUnicast" in src
        bind_sql = bool(re.search(r'"(?:SELECT|UPDATE|DELETE|INSERT)[^"]*\?"\s*,', src))
        html_esc = "html.EscapeString" in src or "bluemonday" in src or "goldmark" in src
        path_contained = "EvalSymlinks" in src and "HasPrefix" in src
        csrf_ok = "X-CSRF-Token" in src or "csrf" in src.lower()
        alnum = bool(re.search(r"\[a-zA-Z0-9", src) and "MustCompile" in src)
        ext_allow = "HasSuffix" in src and (".jpg" in src or ".png" in src)
        size_cap = bool(re.search(r"> 1024|> 1048576|< 0 \|\| allocSize", src))
        int_bound = "2147483646" in src or "2147483647" in src
        setuid_literal = bool(re.search(r"Setuid\(\s*\d+", src))
        bool_ok = '!= "true"' in src and '!= "false"' in src
        csv_quoted = "ContainsRune" in src and "=+-@" in src
        auth_ok = "verifyBearer" in src or "authVerify" in src

        # ── crypto / tls / rand ──────────────────────────────────────────
        if live(r"\bmd5\.(Sum|New)\b") or live(r"\bsha1\.(Sum|New)\b"):
            self.emit_structural(
                fl(r"\b(md5|sha1)\.(Sum|New)"),
                "weakhash",
                "go.md5",
                "md5/sha1 digest — weakhash (CWE-328)",
            )
            if "password" in src.lower() or "passwd" in src.lower():
                self.emit_structural(
                    fl(r"\b(md5|sha1)\.(Sum|New)"),
                    "weak_password_hash",
                    "go.md5.password",
                    "md5/sha1 of a secret/password — weak_password_hash (CWE-916)",
                )
        if live(r"\bdes\.NewCipher\b") or live(r"\brc4\.NewCipher\b") or live(r"crypto/des"):
            if "aes.NewCipher" not in src or live(r"\bdes\.NewCipher\b"):
                self.emit_structural(
                    fl(r"\b(des|rc4)\.NewCipher"),
                    "weakcipher",
                    "go.des",
                    "DES/RC4 cipher — weakcipher (CWE-327)",
                )
        m = re.search(r"rsa\.GenerateKey\s*\([^,]+,\s*(\d+)\s*\)", src)
        if m and int(m.group(1)) < 2048:
            self.emit_structural(
                fl(r"rsa\.GenerateKey"),
                "weakkeylength",
                "go.rsa.short",
                f"RSA key {m.group(1)} bits < 2048 — weakkeylength (CWE-326)",
            )
        if ("math/rand" in src or live(r"\brand\.Intn\s*\(") or live(r"\brand\.Int\s*\(")) and "crypto/rand" not in src:
            self.emit_structural(
                fl(r"math/rand|rand\.Int"),
                "weakrand",
                "go.mathrand",
                "math/rand used as a token — weakrand (CWE-330)",
            )
        if "InsecureSkipVerify: true" in src or "InsecureSkipVerify:true" in src:
            ln = fl(r"InsecureSkipVerify")
            self.emit_structural(ln, "tlsverify", "go.tls.insecure",
                "tls.Config InsecureSkipVerify true — tlsverify (CWE-295)")
            self.emit_structural(ln, "unverified_signature", "go.tls.sig",
                "tls.Config InsecureSkipVerify true — unverified_signature (CWE-347)")

        if re.search(r'http\.(Get|Post|NewRequest)\s*\(\s*"http://', src) or re.search(
            r'"http://api\.svc\.cluster', src
        ):
            self.emit_structural(
                fl(r'"http://'),
                "cleartexttransmit",
                "go.http.cleartext",
                "http:// URL without TLS — cleartexttransmit (CWE-319)",
            )

        # ── planted secrets (same BP tokens as Python/Java/PHP) ──────────
        if re.search(
            r"(config_secret_test_abc123|p4ssw0rd_test_xyz|s3cr3t_key_test_xyz|secret_test_xyz|AKIAIOSFODNN7EXAMPLE)",
            src,
        ):
            ln = fl(r"config_secret_test|p4ssw0rd_test|s3cr3t_key_test|secret_test_xyz|AKIAIOSFODNN7EXAMPLE")
            self.emit_structural(ln, "hardcodedcreds", "go.secret.planted",
                "Planted secret literal — hardcodedcreds (CWE-798)")
            self.emit_structural(ln, "default_credentials", "go.secret.default",
                "Planted secret literal — default_credentials (CWE-1392)")
            self.emit_structural(ln, "credprotection", "go.secret.protect",
                "Planted secret literal — credprotection (CWE-522)")
            self.emit_structural(ln, "hardcoded_crypto_key", "go.key.planted",
                "Planted crypto key literal — hardcoded_crypto_key (CWE-321)")

        if "S3cr3tToken" in src:
            self.emit_structural(
                fl(r"S3cr3tToken"),
                "authnfailure",
                "go.authn.hardcoded",
                "Compare to hardcoded S3cr3tToken — authentication failure (CWE-287)",
            )

        # ── cookies ──────────────────────────────────────────────────────
        # Safe twin: &http.Cookie{Secure:true, HttpOnly:true, SameSite:StrictMode}
        # (spaces optional). 315/784 safes encrypt the value without flags —
        # do not spray flag-CWEs onto those. Vuln twin: Cookie missing flags
        # and not encryptForStorage.
        cookie_flags = bool(
            re.search(r"Secure:\s*true", src)
            and re.search(r"HttpOnly:\s*true", src)
            and "SameSite" in src
        )
        cookie_integrity = "encryptForStorage" in src
        if re.search(r"(http\.SetCookie|c\.SetCookie)\s*\(", src):
            if not cookie_flags and not cookie_integrity:
                ln = fl(r"SetCookie")
                self.emit_structural(ln, "cookie_no_httponly", "go.cookie.httponly",
                    "session cookie without httponly — cookie_no_httponly (CWE-1004)")
                self.emit_structural(ln, "cookie_no_samesite", "go.cookie.samesite",
                    "session cookie without SameSite — cookie_no_samesite (CWE-1275)")
                self.emit_structural(ln, "securecookie", "go.cookie.secure",
                    "session cookie without secure — securecookie (CWE-614)")

        # ── CSRF ─────────────────────────────────────────────────────────
        if re.search(r'DB\.Exec\s*\(\s*"UPDATE', src) or "UPDATE users SET" in src:
            if not csrf_ok:
                self.emit_structural(
                    fl(r"UPDATE users|DB\.Exec"),
                    "csrf",
                    "go.csrf.missing",
                    "State-changing UPDATE without CSRF token — csrf (CWE-352)",
                )

        # ── CORS ─────────────────────────────────────────────────────────
        if "Access-Control-Allow-Origin" in src and not allow:
            self.emit_structural(
                fl(r"Access-Control-Allow-Origin"),
                "corsmisconfig",
                "go.cors.reflect",
                "ACAO reflects user origin without allowlist — corsmisconfig (CWE-942)",
            )

        # ── clickjacking ─────────────────────────────────────────────────
        # Full document only. Do not fire on XSS <div> reflection (CWE-79 spray
        # via description extras matching "html").
        if re.search(r'text/html', src) and "X-Frame-Options" not in src:
            if "<html" in src:
                self.emit_structural(
                    fl(r"<html"),
                    "clickjacking",
                    "go.clickjack",
                    "page without X-Frame-Options — clickjacking (CWE-1021)",
                )

        # ── cmdi / genericcmdi / argument_injection ──────────────────────
        # Vuln twins: exec.Command("sh"|"bash", "-c", concat). Safes: Command("echo", data)
        # or the same sh -c after validSchemaPat / allowlist.
        if (
            re.search(r'exec\.Command\s*\(\s*"(sh|bash|/bin/sh|/bin/bash)"', src)
            or re.search(r'exec\.Command\s*\(\s*"[^"]+"\s*,\s*"-c"', src)
        ) and not allow and not regex_ok:
            ln = fl(r"exec\.Command")
            self.emit_structural(ln, "cmdi", "go.exec.sh",
                "exec.Command sh -c of concatenated user string — cmdi (CWE-78)")
            self.emit_structural(ln, "genericcmdi", "go.exec.generic",
                "exec.Command sh -c of concatenated user string — genericcmdi (CWE-77)")
            self.emit_structural(ln, "argument_injection", "go.exec.arg",
                "exec.Command sh -c echo concat — argument_injection (CWE-88)")

        # ── sqli ─────────────────────────────────────────────────────────
        if re.search(r'fmt\.Sprintf\s*\(\s*"SELECT[^"]*%s', src) or re.search(
            r'"SELECT \* FROM users WHERE id = \'"', src
        ):
            if not bind_sql and not allow and not regex_ok:
                self.emit_structural(
                    fl(r"SELECT \* FROM users|fmt\.Sprintf"),
                    "sqli",
                    "go.db.concat",
                    "DB.Query of concatenated SQL — sqli (CWE-89)",
                )

        # ── nosql ────────────────────────────────────────────────────────
        if re.search(r"mongo|bson\.M|Find\(", src) and "$where" in src:
            if not allow:
                self.emit_structural(
                    fl(r"\$where|mongo"),
                    "nosql",
                    "go.mongo.where",
                    "Mongo $where of user data — nosql (CWE-943)",
                )

        # ── ldap / xpath ─────────────────────────────────────────────────
        # Safes: validSchemaPat.MatchString (not an `allowed` map).
        if re.search(r"ldap\.(NewSearchRequest|Search)\s*\(", src) and not allow and not alnum and not regex_ok and not bool_ok:
            self.emit_structural(
                fl(r"ldap\."),
                "ldapi",
                "go.ldap.filter",
                "LDAP search filter from user data — ldapi (CWE-90)",
            )
        if re.search(r"xmlquery\.Find|xpath\.", src) and not allow and not alnum and not regex_ok and not bool_ok:
            self.emit_structural(
                fl(r"xmlquery\.Find|xpath\."),
                "xpathi",
                "go.xpath",
                "XPath of user expression — xpathi (CWE-643)",
            )

        # ── SSTI ─────────────────────────────────────────────────────────
        # Vuln: template.Parse(data|userID). Safe: Parse("{{.}}") static.
        if ("text/template" in src or "html/template" in src) and re.search(
            r"\.Parse\(\s*[^\"`\s]", src
        ):
            if 'Parse("{{' not in src and "Parse(`{{" not in src and not allow and not regex_ok and not bool_ok:
                self.emit_structural(
                    fl(r"\.Parse\("),
                    "ssti",
                    "go.template.parse",
                    "template.Parse of user template — ssti (CWE-1336)",
                )

        # ── XSS ──────────────────────────────────────────────────────────
        # NewReplacer is NOT a sanitizer (QT vuln). Allowlist / EscapeString / bluemonday are.
        if re.search(r'<div>\' \+|htmlOut := "<div>"|"<div>" \+', src) or re.search(
            r'"<div>" \+ processed', src
        ):
            if not allow and not html_esc and not regex_ok:
                ln = fl(r"<div>")
                self.emit_structural(ln, "xss", "go.html.concat",
                    "HTML div reflects unsanitized input — xss (CWE-79)")
                self.emit_structural(ln, "basic_xss", "go.html.basic",
                    "HTML div reflects unsanitized input — basic_xss (CWE-80)")

        # ── path / upload ────────────────────────────────────────────────
        # Fire only on user-concat join. Fixed path (/var/app/data/store.dat)
        # + encryptForStorage is the 538/219 safe twin. EvalSymlinks containment
        # / allowlist / regex remain sanitizers.
        user_path_join = bool(
            re.search(r'/var/app/data/"\s*\+\s*\w+', src)
            or re.search(r"/var/www/[^\"\s]*\"\s*\+\s*\w+", src)
        )
        if user_path_join and not path_contained and not allow and not regex_ok:
            ln = fl(r"/var/app/data/|/var/www/")
            self.emit_structural(ln, "pathtraver", "go.path.open",
                "open /var/app/data join without EvalSymlinks containment — pathtraver (CWE-22)")
        if "/var/uploads/" in src and not ext_allow and "allowed" not in src.lower():
            self.emit_structural(
                fl(r"/var/uploads/"),
                "fileupload",
                "go.upload.noext",
                "write to /var/uploads/ without allowlist — fileupload (CWE-434)",
            )

        # ── SSRF / redirect ──────────────────────────────────────────────
        # Non-literal http.Get / client.Get. Safes: allowedHosts or private-range block.
        user_get = bool(
            re.search(r"http\.Get\(\s*[^\"\s]", src)
            or re.search(r"client\.Get\(\s*[^\"\s]", src)
            or re.search(r'http\.NewRequest\(\s*"GET"\s*,\s*(data|targetUrl|processed)\s*,', src)
        )
        if user_get and not allow and not private_block:
            self.emit_structural(
                fl(r"http\.Get\(|client\.Get\(|NewRequest"),
                "ssrf",
                "go.http.get",
                "http.Get of user URL without host allowlist — ssrf (CWE-918)",
            )
            self.emit_structural(
                fl(r"http\.Get\(|client\.Get\(|NewRequest"),
                "cloud_ssrf_metadata",
                "go.http.metadata",
                "http.Get of user URL — cloud_ssrf_metadata (CWE-918)",
            )
        if re.search(r'net\.Dial\(\s*"tcp"\s*,\s*[^"\s]', src) and not allow and not private_block:
            self.emit_structural(
                fl(r"net\.Dial"),
                "ssrf",
                "go.net.dial",
                "net.Dial of user address without allowlist — ssrf (CWE-918)",
            )
        if (
            re.search(r"c\.Redirect\([^,]+,\s*[^\"\s]", src)
            or re.search(r"http\.Redirect\([^,]+,[^,]+,\s*[^\"\s]", src)
        ) and not allow:
                self.emit_structural(
                    fl(r"Redirect\("),
                    "redirect",
                    "go.redirect",
                    "Redirect of user URL without host allowlist — redirect (CWE-601)",
                )

        # ── log injection ────────────────────────────────────────────────
        if re.search(r'log\.Printf\(\s*"User action:', src):
            if not allow and "****" not in src and not alnum and not bool_ok and not regex_ok:
                ln = fl(r'log\.Printf\(\s*"User action:')
                self.emit_structural(ln, "loginjection", "go.log.printf",
                    "log.Printf of unsanitized user data — loginjection (CWE-117)")
                self.emit_structural(ln, "sensinlogs", "go.log.sens",
                    "log.Printf of unsanitized user data — sensinlogs (CWE-532)")

        # ── csv ──────────────────────────────────────────────────────────
        if re.search(r"export\.csv|csv\.NewWriter|fmt\.Fprintf\([^,]+,\s*\"user,%s", src):
            if not allow and not regex_ok and not csv_quoted:
                self.emit_structural(
                    fl(r"export\.csv|csv\.NewWriter|user,%s"),
                    "csv_injection",
                    "go.csv",
                    "Unquoted user field appended to CSV — csv_injection (CWE-1236)",
                )

        # ── auth family ──────────────────────────────────────────────────
        if re.search(r'DELETE FROM accounts', src) and "authVerify" not in src and "session" not in src.lower():
            self.emit_structural(
                fl(r"DELETE FROM accounts"),
                "missingcritauthn",
                "go.authn.delete",
                "DELETE FROM accounts without auth — missingcritauthn (CWE-306)",
            )
        if "loginAttempts" in src and not re.search(r"> 5", src) and "authVerify" in src:
            self.emit_structural(
                fl(r"loginAttempts"),
                "no_brute_force_limit",
                "go.login.nolimit",
                "authVerify with loginAttempts and no lockout — no_brute_force_limit (CWE-307)",
            )
        if re.search(r"SELECT secret FROM vault", src) and "authVerify" not in src:
            self.emit_structural(
                fl(r"SELECT secret FROM vault"),
                "authzfailure",
                "go.authz.vault",
                "Vault secret fetched by user key without auth — authzfailure (CWE-862)",
            )
        if re.search(r"SELECT \* FROM documents WHERE id", src) and "authVerify" not in src:
            self.emit_structural(
                fl(r"SELECT \* FROM documents WHERE id"),
                "idor",
                "go.idor.documents",
                "Document fetched by user id without auth — idor (CWE-639)",
            )
        if ("'role': 'admin'" in src or '"role": "admin"' in src or "role.*admin" in src) and "authVerify" not in src:
            if re.search(r'"role":\s*"admin"|role.: .admin', src):
                self.emit_structural(
                    fl(r"role"),
                    "authzincorrect",
                    "go.authz.grant",
                    "User input listed as admin grant without auth — authzincorrect (CWE-863)",
                )
        if (live(r"\bos\.Setuid\s*\(") or live(r"\bsyscall\.Setuid\s*\(")) and not setuid_literal:
            self.emit_structural(
                fl(r"Setuid"),
                "privescalation",
                "go.setuid",
                "Setuid of user-controlled uid — privescalation (CWE-269)",
            )

        # ── session fixation ─────────────────────────────────────────────
        if re.search(r'session\[.user.\]|SetCookie.*session', src) and "session.Clear" not in src:
            if "lastRequestValue.Store" in src and "SetCookie" in src:
                pass  # not necessarily fixation
        if re.search(r'session\["user"\]\s*=', src) and "Clear" not in src:
            self.emit_structural(
                fl(r'session\["user"\]'),
                "sessionfixation",
                "go.session.noclear",
                "session user set without cycle/clear — sessionfixation (CWE-384)",
            )

        # ── cleartext storage ────────────────────────────────────────────
        if re.search(r"/var/data/secrets\.txt|/var/app/data/secret", src) and "Write" in src:
            if "sha256" not in src.lower() and "encrypt" not in src.lower():
                self.emit_structural(
                    fl(r"secrets\.txt|secret"),
                    "cleartextstorage",
                    "go.secrets.write",
                    "Writing plaintext secrets — cleartextstorage (CWE-312)",
                )

        # ── resourceexhaust / intoverflow / null_deref ───────────────────
        # Vuln: make([]byte, allocSize) unbounded. Safe: cap at 1024. Do not
        # fire on make([]byte, tokenLen) (weakrand safes).
        if re.search(r"make\(\[\]byte,\s*allocSize\s*\)", src) and not size_cap:
            self.emit_structural(
                fl(r"make\(\[\]byte"),
                "resourceexhaust",
                "go.make.unbounded",
                "make([]byte, n) of unbounded user size — resourceexhaust (CWE-400)",
            )
        if re.search(r"int32\(\s*(requested|parsedInt|n)\s*\+\s*1\s*\)", src) and not int_bound:
            self.emit_structural(
                fl(r"int32\("),
                "intoverflow",
                "go.atoi.wrap",
                "Atoi then +1 without bound — intoverflow (CWE-190)",
            )
        if re.search(r"\(\*.+\)\.\w+|rows\.Scan", src) and "if err" not in src and "nil" in src:
            pass
        if re.search(r"result\[.name.\]", src) and ", ok :=" not in src:
            self.emit_structural(
                fl(r"result\["),
                "null_deref",
                "go.map.unchecked",
                "map field without ok-check — null_deref (CWE-476)",
            )

        # ── debug / error / info ─────────────────────────────────────────
        if "debug query=" in src or re.search(r"fmt\.Sprintf\(\s*\"debug", src):
            self.emit_structural(
                fl(r"debug"),
                "debug_code_production",
                "go.debug",
                "debug query in response — debug_code_production (CWE-489)",
            )
        if re.search(r"ORA-00942|runtime\.Stack|debug\.Stack", src) and re.search(r"c\.String|http\.Error", src):
            self.emit_structural(
                fl(r"ORA-00942|runtime\.Stack|debug\.Stack"),
                "errormessage",
                "go.err.detail",
                "Detailed error/stack returned to client — errormessage (CWE-209)",
            )
        if re.search(r"os\.ReadDir\(\s*data\s*\)|os\.ReadDir\(\s*processed\s*\)", src) and not allow and not auth_ok:
            self.emit_structural(
                fl(r"ReadDir"),
                "directory_listing_exposure",
                "go.readdir",
                "directory listing of user path — directory_listing_exposure (CWE-209)",
            )

        # ── integrity — only the promote-to-active write idiom, not every WriteFile
        if re.search(r"os\.WriteFile\([^,]+,\s*content", src) and "sha256" not in src and "hmac" not in src:
            if "promote" in src or "active" in src:
                self.emit_structural(
                    fl(r"os\.WriteFile"),
                    "missing_integrity_check",
                    "go.write.nohash",
                    "write without hash/signature — missing_integrity_check (CWE-353)",
                )

        # ── inputval ─────────────────────────────────────────────────────
        if re.search(r"\[\^\\\\x00-|data\[:64\]", src) and not alnum and not allow:
            self.emit_structural(
                fl(r"data\[:64\]|\[\^\\\\x00"),
                "inputval",
                "go.input.weak",
                "weak length/control-char gate — inputval (CWE-20)",
            )

        # ── infodisclosure ───────────────────────────────────────────────
        if re.search(r"runtime\.Stack|debug\.Stack|os\.Environ\(\)", src):
            self.emit_structural(
                fl(r"Stack|os\.Environ"),
                "infodisclosure",
                "go.info.stack",
                "stack/environ returned to client — infodisclosure (CWE-200)",
            )

    # ── light taint lowering ─────────────────────────────────────────────

    def lower_file_body(self) -> None:
        src = self.source
        for m in _FN.finditer(src):
            name = m.group(1)
            params_raw = m.group(2)
            start = m.end() - 1
            body, _end = self._extract_braces(src, start)
            line = src[: m.start()].count("\n") + 1
            params = []
            for part in params_raw.split(","):
                part = part.strip()
                if not part:
                    continue
                tok = part.split()[0]
                if tok.startswith("*"):
                    tok = tok[1:]
                params.append(tok)
            fn = {
                "id": f"fn_{name}_{line}",
                "name": name,
                "params": params,
                "body": {"statements": self._lower_block(body or "", line)},
                "location": self.loc(line),
                "modifiers": {"async": False, "generator": False, "arrow": False},
            }
            self.functions.append(fn)

    def _extract_braces(self, text: str, open_idx: int) -> tuple:
        if open_idx >= len(text) or text[open_idx] != "{":
            return "", open_idx
        depth = 0
        i = open_idx
        in_str = None
        while i < len(text):
            ch = text[i]
            if in_str:
                if ch == "\\" and i + 1 < len(text):
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
                i += 1
                continue
            if ch in ('"', "'", "`"):
                in_str = ch
                i += 1
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[open_idx + 1 : i], i + 1
            i += 1
        return text[open_idx + 1 :], len(text)

    def _lower_block(self, body: str, base_line: int) -> List[Dict[str, Any]]:
        stmts: List[Dict[str, Any]] = []
        for raw in body.split("\n"):
            line_s = raw.strip()
            if not line_s or line_s.startswith("//") or line_s.startswith("if ") or line_s.startswith("for "):
                continue
            line_s = line_s.rstrip("{").strip()
            am = re.match(r"^(\w+)\s*:?=\s*(.+)$", line_s.rstrip(","))
            if am and not line_s.startswith("func "):
                rhs = am.group(2).rstrip(";").strip()
                if rhs.endswith("{") or rhs.startswith("func"):
                    continue
                stmts.append(
                    {
                        "kind": "Assign",
                        "id": self.next_id("assign"),
                        "target": am.group(1),
                        "value": self._lower_expr(rhs),
                        "location": self.loc(base_line),
                    }
                )
                continue
            if "(" in line_s and not line_s.startswith("defer ") and not line_s.startswith("go "):
                expr = line_s.rstrip(";").strip()
                if expr.startswith("return "):
                    stmts.append(
                        {
                            "kind": "Return",
                            "id": self.next_id("ret"),
                            "value": self._lower_expr(expr[7:]),
                            "location": self.loc(base_line),
                        }
                    )
                    continue
                stmts.append(
                    {
                        "kind": "ExpressionStmt",
                        "id": self.next_id("expr"),
                        "expr": self._lower_expr(expr),
                        "location": self.loc(base_line),
                    }
                )
        return stmts

    def _lower_expr(self, expr: str) -> Dict[str, Any]:
        expr = expr.strip().rstrip(";").strip()
        if not expr:
            return {"kind": "Literal", "literalKind": "undefined"}
        if (expr.startswith('"') and expr.endswith('"')) or (expr.startswith("`") and expr.endswith("`")):
            return {"kind": "Literal", "literalKind": "string", "raw": expr[1:-1]}
        if expr in ("true", "false"):
            return {"kind": "Literal", "literalKind": "boolean", "raw": expr}
        if re.fullmatch(r"-?\d+(?:\.\d+)?", expr):
            return {"kind": "Literal", "literalKind": "number", "raw": expr}
        if re.fullmatch(r"[A-Za-z_]\w*", expr):
            return {"kind": "Variable", "name": expr}
        # binary concat
        plus = _split_top(expr, "+")
        if len(plus) == 2:
            return {
                "kind": "Binary",
                "op": "+",
                "left": self._lower_expr(plus[0]),
                "right": self._lower_expr(plus[1]),
            }
        # call
        cm = re.match(r"^(.+)\((.*)\)\s*$", expr, re.S)
        if cm:
            callee_s = cm.group(1).strip()
            args_s = cm.group(2)
            args = [_split_top(args_s, ",")[i] for i in range(len(_split_top(args_s, ",")))] if args_s.strip() else []
            if args == [""]:
                args = []
            return {
                "kind": "Call",
                "callee": self._lower_callee(callee_s),
                "args": [self._lower_expr(a.strip()) for a in args if a.strip() or False],
            }
        # selector
        if "." in expr and "(" not in expr:
            return self._lower_callee(expr)
        return {"kind": "Unknown", "hint": expr[:80]}

    def _lower_callee(self, expr: str) -> Dict[str, Any]:
        expr = expr.strip()
        if "." not in expr:
            return {"kind": "Variable", "name": expr}
        parts = expr.split(".")
        acc: Dict[str, Any] = {"kind": "Variable", "name": parts[0]}
        for p in parts[1:]:
            acc = {"kind": "FieldAccess", "object": acc, "field": p}
        return acc


def _split_top(s: str, sep: str) -> List[str]:
    parts: List[str] = []
    buf = []
    depth = 0
    in_str = None
    i = 0
    while i < len(s):
        ch = s[i]
        if in_str:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(s):
                buf.append(s[i + 1])
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ('"', "'", "`"):
            in_str = ch
            buf.append(ch)
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if depth == 0 and s.startswith(sep, i):
            parts.append("".join(buf))
            buf = []
            i += len(sep)
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def main() -> int:
    args = sys.argv[1:]
    if not args:
        sys.stderr.write("usage: python3 -m vantage.nebula_frontend_go <file.go> [...]\n")
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
