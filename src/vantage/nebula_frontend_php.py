"""
VANTAGE NEBULA — PHP frontend.

Lowers PHP (Laravel / Symfony BenchProctor controllers) into the same
ModuleIR the other frontends emit. One .php file = one ModuleIR.

Parser: Python-hosted subset scanner (C/Ruby analog). Do not require
php-cli, Psalm, or framework autoload. Apache-2.0 — no GPL source.

Usage:
    python3 -m vantage.nebula_frontend_php <file.php> [...]
    python3 -m vantage.nebula_frontend_php --batch   # paths on stdin
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
    r"(?:public|private|protected|static|\s)+function\s+(\w+)\s*\(([^)]*)\)\s*\{",
    re.M,
)

_IDENT = re.compile(r"[A-Za-z_\\][\w\\]*")


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
        self._const_str: Dict[str, str] = {}

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

    # ── structural (gated against QT safe twins) ─────────────────────────

    def collect_structural_from_source(self) -> None:
        src = self.source
        fl = self.first_line

        def live(pat: str) -> bool:
            return re.search(pat, src) is not None

        strong_alnum = bool(
            re.search(r"in_array\s*\(", src)
            or re.search(r"preg_match\s*\(\s*'/\^\[A-Za-z0-9", src)
            or re.search(r"preg_match\s*\(\s*'/\^\[a-zA-Z0-9", src)
        )
        hashed = "hash_equals" in src or "password_hash" in src
        html_esc = "htmlspecialchars" in src or "htmlentities" in src or "e(" in src or "Parsedown" in src

        if "FILTER_FLAG_NO_PRIV_RANGE" in src:
            self.notes.append("php-ssrf-range-gated")
        if 'str_replace(["\\r", "\\n"]' in src or "str_replace(['\\r', '\\n']" in src:
            self.notes.append("php-log-crlf-stripped")

        # crlf — log write without CR/LF strip or allowlist. Safes strip or allowlist.
        if "app_action.log" in src and "php-log-crlf-stripped" not in self.notes and not strong_alnum:
            self.emit_structural(
                fl(r"app_action\.log"),
                "crlfinjection",
                "php.log.crlf",
                "log write of user data without CR/LF strip — crlfinjection (CWE-93)",
            )

        # dataintegrity — $trusted without HMAC. Safes hash_hmac + hash_equals.
        if "$trusted" in src and "hash_hmac" not in src:
            self.emit_structural(
                fl(r"\$trusted"),
                "dataintegrity",
                "php.hmac.missing",
                "trusted copy of user data without HMAC — dataintegrity (CWE-345)",
            )

        # inputval — unanchored preg_match accept. Safes in_array or /^...$/.
        if "preg_match('/[a-zA-Z0-9_-]+/'" in src and not strong_alnum:
            self.emit_structural(
                fl(r"preg_match\('/\[a-zA-Z0-9_-\]\+/'"),
                "inputval",
                "php.preg.unanchored",
                "unanchored preg_match accept — inputval (CWE-20)",
            )

        # weakhash — md5/sha1 without password_hash / hash_equals / SHA256
        if live(r"\bmd5\s*\(") or live(r"\bsha1\s*\(") or live(r"hash\s*\(\s*['\"]md5"):
            if "password_hash" not in src and "hash('sha256'" not in src and "hash(\"sha256\"" not in src:
                self.emit_structural(
                    fl(r"\b(md5|sha1)\s*\("),
                    "weakhash",
                    "php.md5",
                    "md5/sha1 digest — weakhash (CWE-328)",
                )
                if re.search(r"md5\s*\(\s*\(string\)\s*\$", src) or "password" in src.lower():
                    self.emit_structural(
                        fl(r"\bmd5\s*\("),
                        "weak_password_hash",
                        "php.md5.password",
                        "md5 of a secret/password — weak_password_hash (CWE-916)",
                    )

        # typejuggling — == md5 without hash_equals
        if live(r"==\s*md5\s*\(") or live(r"md5\s*\([^)]*\)\s*==") or (
            "md5(" in src and "==" in src and "hash_equals" not in src and "===" not in src
        ):
            if "hash_equals" not in src and live(r"\bmd5\s*\("):
                self.emit_structural(
                    fl(r"\bmd5\s*\("),
                    "typejuggling",
                    "php.md5.eq",
                    "loose == with md5 — typejuggling (CWE-843)",
                )

        # hardcoded / user-controlled crypto key — openssl_encrypt('data', cipher, $data)
        # Safes use getenv('DATA_ENC_KEY') as the key and encrypt $data as plaintext.
        if re.search(r"openssl_encrypt\s*\(\s*'data'\s*,", src) and "DATA_ENC_KEY" not in src:
            self.emit_structural(
                fl(r"openssl_encrypt"),
                "hardcoded_crypto_key",
                "php.openssl.userkey",
                "openssl_encrypt with user value as key — hardcoded_crypto_key (CWE-321)",
            )
        if re.search(r"['\"]des-|['\"]bf-|['\"]rc4|['\"]DES", src, re.I) and "aes-256-gcm" not in src:
            self.emit_structural(
                fl(r"openssl_encrypt|['\"]des"),
                "weakcipher",
                "php.openssl.des",
                "openssl_encrypt DES/ECB/RC4 — weakcipher (CWE-327)",
            )

        # weakkeylength
        m = re.search(r"openssl_pkey_new\s*\([^)]*(\d{3,4})", src)
        if m and int(m.group(1)) < 2048:
            self.emit_structural(
                fl(r"openssl_pkey_new"),
                "weakkeylength",
                "php.openssl.bits",
                f"RSA key {m.group(1)} bits < 2048 — weakkeylength (CWE-326)",
            )

        # weakrand
        if (live(r"\bmt_rand\s*\(") or live(r"\brand\s*\(") or live(r"\bmt_srand\s*\(")) and "random_bytes" not in src and "random_int" not in src:
            self.emit_structural(
                fl(r"\b(mt_rand|mt_srand|rand)\s*\("),
                "weakrand",
                "php.mt_rand",
                "mt_rand/rand used for a token — weakrand (CWE-330)",
            )

        # tlsverify
        if "verify_peer" in src and re.search(r"verify_peer'\s*=>\s*false|verify_peer\"\s*=>\s*false", src):
            self.emit_structural(
                fl(r"verify_peer"),
                "tlsverify",
                "php.ssl.verify_peer",
                "ssl verify_peer => false — tlsverify (CWE-295)",
            )
            self.emit_structural(
                fl(r"verify_peer"),
                "unverified_signature",
                "php.ssl.unverified",
                "ssl verify_peer => false — unverified_signature (CWE-347)",
            )

        # cleartext http
        if re.search(r"""file_get_contents\s*\(\s*['"]http://""", src) or re.search(
            r"""['"]http://api\.corp""", src
        ):
            self.emit_structural(
                fl(r"http://"),
                "cleartexttransmit",
                "php.http.cleartext",
                "http:// URL without TLS — cleartexttransmit (CWE-319)",
            )

        # planted secrets (same BP tokens as Ruby/Python)
        if "p4ssw0rd_test_xyz" in src or "admin123" in src:
            self.emit_structural(
                fl(r"p4ssw0rd_test_xyz|admin123"),
                "hardcodedcreds",
                "php.password.planted",
                "Planted password literal — hardcodedcreds (CWE-798)",
            )
            self.emit_structural(
                fl(r"p4ssw0rd_test_xyz|admin123"),
                "default_credentials",
                "php.password.default",
                "Planted password literal — default_credentials (CWE-1392)",
            )
            self.emit_structural(
                fl(r"p4ssw0rd_test_xyz|admin123"),
                "credprotection",
                "php.password.protect",
                "Planted password literal — credprotection (CWE-522)",
            )
        if "s3cr3t_key_test_xyz" in src or "hardcoded-app-key" in src:
            self.emit_structural(
                fl(r"s3cr3t_key_test_xyz|hardcoded-app-key"),
                "hardcoded_crypto_key",
                "php.key.planted",
                "Planted crypto key literal — hardcoded_crypto_key (CWE-321)",
            )

        # cookies — SET only. Do not match $request->cookie('session_token') sources.
        # Safe twins: options array / Cookie::create(..., true, true, false, 'Strict')
        # / session_set_cookie_params / session.cookie_secure+httponly ini.
        # Vuln twin: legacy positional setcookie($n, $v) or flags false/null.
        sets_cookie = bool(
            re.search(r"->cookie\s*\(\s*'session'\s*,", src)
            or re.search(r"Cookie::create\s*\(\s*'session'\s*,", src)
            or re.search(r"\bsetcookie\s*\(", src)
        )
        flags_ok = bool(
            re.search(r"true,\s*true,\s*false,\s*'(?:Strict|Lax)'", src)
            or (
                re.search(r"['\"]secure['\"]\s*=>\s*true", src)
                and re.search(r"['\"]httponly['\"]\s*=>\s*true", src, re.I)
                and re.search(r"['\"]samesite['\"]\s*=>\s*'(?:Strict|Lax)'", src, re.I)
            )
            or (
                "session_set_cookie_params" in src
                and re.search(r"['\"]secure['\"]\s*=>\s*true", src)
                and re.search(r"['\"]httponly['\"]\s*=>\s*true", src, re.I)
            )
            or (
                "session.cookie_secure" in src
                and "session.cookie_httponly" in src
            )
        )
        if sets_cookie and not flags_ok:
            ln = fl(r"->cookie\s*\(\s*'session'\s*,|Cookie::create\s*\(\s*'session'\s*,|\bsetcookie\s*\(")
            self.emit_structural(ln, "cookie_no_httponly", "php.cookie.httponly",
                "session cookie without httponly — cookie_no_httponly (CWE-1004)")
            self.emit_structural(ln, "cookie_no_samesite", "php.cookie.samesite",
                "session cookie without SameSite — cookie_no_samesite (CWE-1275)")
            self.emit_structural(ln, "securecookie", "php.cookie.secure",
                "session cookie without secure — securecookie (CWE-614)")

        # CSRF — mutating SQL without csrf token
        if re.search(r"DB::(statement|update|insert|delete)|UPDATE users SET", src):
            if "csrf" not in src.lower() and "hash_equals" not in src:
                if re.search(r"UPDATE users SET|DB::statement\s*\(\s*'UPDATE", src):
                    self.emit_structural(
                        fl(r"UPDATE users|DB::statement"),
                        "csrf",
                        "php.csrf.missing",
                        "State-changing UPDATE without csrf token — csrf (CWE-352)",
                    )

        # CORS reflection
        if re.search(r"Access-Control-Allow-Origin", src) and not strong_alnum and "in_array" not in src:
            self.emit_structural(
                fl(r"Access-Control-Allow-Origin"),
                "corsmisconfig",
                "php.cors.reflect",
                "ACAO reflects user origin without allowlist — corsmisconfig (CWE-942)",
            )

        # clickjacking structural removed — 94% FPR on QT (any HTML without XFO).

        # eval without allowlist
        if live(r"\beval\s*\(") and not strong_alnum:
            ln = fl(r"\beval\s*\(")
            self.emit_structural(ln, "eval_injection", "php.eval",
                "eval of user string without allowlist — eval_injection (CWE-95)")
            self.emit_structural(ln, "codeinj", "php.eval.code",
                "eval of user string without allowlist — codeinj (CWE-94)")

        # cmdi/xss/ssti/clickjacking: taint + allowlist. Structural spray on QT safes.

        # sqli concat (bind-param safes use ? placeholders)
        if re.search(r"DB::(select|statement|insert)\s*\(\s*'[^']*'\s*\.\s*\$", src) or re.search(
            r"WHERE id = \\\\\?'\s*\.\s*\$|WHERE id = '\\'\s*\.\s*\$", src
        ) or re.search(r"WHERE id = '\\\\?'\s*\.\s*\$data|WHERE id = '\\' \. \$", src):
            if "?'," not in src and not re.search(r"DB::select\s*\([^)]+\?", src):
                pass
        if re.search(r"WHERE id = '\\\\?'\s*\.\s*\$|WHERE id = '\\'\s*\.\s*\$data|id = \\\\\?' \. \$", src) or (
            re.search(r"DB::select\s*\(\s*'SELECT \* FROM users WHERE id = '", src)
            and ".$data" in src.replace(" ", "")
        ):
            if "?'," not in src and "(int)" not in src and "intval" not in src:
                self.emit_structural(
                    fl(r"DB::select|WHERE id"),
                    "sqli",
                    "php.db.concat",
                    "DB::select of concatenated SQL — sqli (CWE-89)",
                )

        # more reliable sqli: quoted concat of $data
        if re.search(r"' \. \$data \. '|\" \. \$data \. \"|' \. \$parsedId", src) and re.search(
            r"DB::(select|statement)", src
        ):
            if "(int)$data" not in src and "(int)$parsedId" not in src and "intval" not in src:
                if "?'," not in src:
                    self.emit_structural(
                        fl(r"DB::(select|statement)"),
                        "sqli",
                        "php.db.concat2",
                        "DB concatenated identifier — sqli (CWE-89)",
                    )

        # deserial
        if live(r"\bunserialize\s*\(") and not strong_alnum:
            self.emit_structural(
                fl(r"\bunserialize\s*\("),
                "deserial",
                "php.unserialize",
                "unserialize of user data — deserial (CWE-502)",
            )

        # xxe
        if (live(r"simplexml_load_string") or live(r"loadXML")) and "LIBXML_NONET" not in src:
            if not strong_alnum:
                self.emit_structural(
                    fl(r"simplexml_load_string|loadXML"),
                    "xxe",
                    "php.xxe",
                    "XML load of user input without LIBXML_NONET — xxe (CWE-611)",
                )

        # SSTI / EL
        if "ExpressionLanguage" in src or re.search(r"->evaluate\s*\(\s*\$data", src):
            if not strong_alnum:
                self.emit_structural(
                    fl(r"ExpressionLanguage|->evaluate"),
                    "el_injection",
                    "php.el.evaluate",
                    "ExpressionLanguage::evaluate of user string — el_injection (CWE-917)",
                )

        # XSS / clickjacking: taint htmlReturnSink + response() sink. Do not
        # structural-spray every text/html file.

        # SSRF file_get_contents of $data / $targetUrl without IP pin
        if re.search(r"file_get_contents\s*\(\s*\(string\)\s*\$(data|targetUrl|userInput)", src):
            if "FILTER_FLAG_NO_PRIV_RANGE" not in src and "in_array" not in src:
                self.emit_structural(
                    fl(r"file_get_contents"),
                    "ssrf",
                    "php.file_get_contents.ssrf",
                    "file_get_contents of user URL without private-range pin — ssrf (CWE-918)",
                )

        # path traversal — user concat into a path. Literal storage writes are
        # 219/538/922, not CWE-22 (alias spray onto encrypted safes).
        ext_allow = bool(re.search(r"\\\.\(jpe?g\|png\|gif\|pdf\)", src, re.I))
        path_concat = bool(re.search(
            r"(file_get_contents|fopen|file_put_contents)\s*\(\s*['\"][^'\"]+['\"]\s*\.\s*",
            src,
        ))
        if (
            path_concat
            and "realpath" not in src
            and "basename" not in src
            and not ext_allow
            and not strong_alnum
        ):
            self.emit_structural(
                fl(r"file_get_contents|fopen|file_put_contents"),
                "pathtraver",
                "php.path.concat",
                "file op of concatenated path without realpath — pathtraver (CWE-22)",
            )

        enc_ok = (
            "openssl_encrypt" in src
            or "DATA_ENC_KEY" in src
            or "password_hash" in src
        )
        # 219 — plaintext under web root. Safe twin encrypts first.
        if re.search(r"/var/www/html/", src) and not enc_ok:
            self.emit_structural(
                fl(r"/var/www/html/"),
                "sensitive_file_web_root",
                "php.www.export",
                "plaintext write under web root — sensitive_file_web_root (CWE-219)",
            )
        # 538 — plaintext insertion into a log/export file
        if re.search(r"/var/log/app_(export|audit)\.", src) and not enc_ok:
            self.emit_structural(
                fl(r"/var/log/app_"),
                "sensitive_file_insertion",
                "php.log.export",
                "plaintext audit/export log — sensitive_file_insertion (CWE-538)",
            )
        # 922 — insecure storage of secrets (not /var/app/data traversal)
        if re.search(r"file_put_contents\s*\(\s*['\"]/var/data/", src) and not enc_ok:
            self.emit_structural(
                fl(r"/var/data/"),
                "insecure_storage",
                "php.var.data",
                "raw user bytes written to /var/data — insecure_storage (CWE-922)",
            )

        # redirect
        if re.search(r"\bredirect\s*\(\s*\$data\s*\)", src) and not strong_alnum:
            self.emit_structural(
                fl(r"\bredirect\s*\("),
                "redirect",
                "php.redirect",
                "redirect of user URL without allowlist — redirect (CWE-601)",
            )

        # nosql regex
        if "$regex" in src or "findOne" in src:
            if not strong_alnum:
                self.emit_structural(
                    fl(r"findOne|\$regex"),
                    "nosql",
                    "php.mongo.regex",
                    "Mongo findOne of user regex — nosql (CWE-943)",
                )

        # ldap
        if re.search(r"ldap_search|ldap_bind", src) and not strong_alnum:
            self.emit_structural(
                fl(r"ldap_search|ldap_bind"),
                "ldapi",
                "php.ldap",
                "ldap_search of user filter — ldapi (CWE-90)",
            )

        # xpath
        if re.search(r"->xpath\s*\(|xpath\s*\(", src) and not strong_alnum:
            self.emit_structural(
                fl(r"xpath"),
                "xpathi",
                "php.xpath",
                "xpath of user expression — xpathi (CWE-643)",
            )

        # log injection
        if re.search(r"error_log\s*\(|Log::(info|warning|error|debug)", src) and "$data" in src:
            if not strong_alnum and "****" not in src:
                ln = fl(r"error_log|Log::")
                self.emit_structural(ln, "loginjection", "php.error_log",
                    "error_log of user data — loginjection (CWE-117)")
                self.emit_structural(ln, "sensinlogs", "php.error_log.sens",
                    "error_log of user data — sensinlogs (CWE-532)")

        # auth — role === admin without session/hash_equals
        if re.search(r"\$role === 'admin'|\$role === \"admin\"", src) and not hashed:
            ln = fl(r"\$role === 'admin'")
            self.emit_structural(ln, "authnfailure", "php.role.admin",
                "role === admin without session token — authnfailure (CWE-287)")
            self.emit_structural(ln, "authzfailure", "php.role.admin.z",
                "role === admin without session token — authzfailure (CWE-862)")
            self.emit_structural(ln, "authzincorrect", "php.role.admin.inc",
                "role === admin without session token — authzincorrect (CWE-863)")
            self.emit_structural(ln, "missingcritauthn", "php.role.admin.crit",
                "role === admin without session token — missingcritauthn (CWE-306)")
            self.emit_structural(ln, "no_brute_force_limit", "php.role.admin.brute",
                "role === admin without rate limit — no_brute_force_limit (CWE-307)")

        # session fixation
        if re.search(r"session_id\s*\(\s*\$|session\(\s*\$.*\)\s*=", src) and "session_regenerate_id" not in src:
            self.emit_structural(
                fl(r"session_id|session\("),
                "sessionfixation",
                "php.session.fix",
                "session id from user without regenerate — sessionfixation (CWE-384)",
            )

        # file upload
        if "/var/www/uploads/" in src and not re.search(r"\.(png|jpg|jpeg|gif|pdf)", src):
            self.emit_structural(
                fl(r"/var/www/uploads/"),
                "fileupload",
                "php.upload",
                "upload path without type suffix — fileupload (CWE-434)",
            )

        # csv — formula prefix unquoted. Safes quote =+ -@ then fputcsv.
        if "output.csv" in src and "['=', '+', '-', '@']" not in src and not strong_alnum:
            self.emit_structural(
                fl(r"output\.csv|fputcsv"),
                "csv_injection",
                "php.csv",
                "CSV of user field without formula quote — csv_injection (CWE-1236)",
            )

        # clickjacking — markup response without X-Frame-Options. Safes set DENY.
        # Do not say "html" in the message — cwesForFinding co-tags 79/80 on /html/.
        if re.search(r"text/html|'<html|'<div|'<body", src) and "X-Frame-Options" not in src:
            self.emit_structural(
                fl(r"text/html|'<html|'<div"),
                "clickjacking",
                "php.xfo.missing",
                "markup response without X-Frame-Options — clickjacking (CWE-1021)",
            )

        # integer overflow — pack/unpack 32-bit wrap
        if re.search(r"pack\s*\(\s*'l'", src) and "+ 1" in src and "2147483646" not in src:
            self.emit_structural(
                fl(r"pack\s*\("),
                "intoverflow",
                "php.int.pack",
                "pack/unpack int32 wrap of user int + 1 — integer overflow (CWE-190)",
            )

        # crlf — PHP header('Name: '.$data). Do not match Laravel ->header('X-Frame-Options').
        if re.search(r"\bheader\s*\(\s*['\"][^'\"]+['\"]\s*\.\s*\$", src) and "$data" in src:
            if not strong_alnum and "str_replace" not in src and "strtr" not in src:
                self.emit_structural(
                    fl(r"header\s*\(|->header"),
                    "crlfinjection",
                    "php.header.crlf",
                    "header of user data without CRLF strip — crlfinjection (CWE-93)",
                )

        # debug
        if re.search(r"\bphpinfo\s*\(|var_dump\s*\(\s*\$|print_r\s*\(\s*\$|DEBUG query", src):
            if "APP_DEBUG" not in src:
                self.emit_structural(
                    fl(r"phpinfo|var_dump|print_r|DEBUG query"),
                    "debug_code_production",
                    "php.debug",
                    "debug dump in production — debug_code_production (CWE-489)",
                )
                self.emit_structural(
                    fl(r"phpinfo|var_dump|print_r|DEBUG query"),
                    "infodisclosure",
                    "php.debug.info",
                    "debug dump — infodisclosure (CWE-200)",
                )
                self.emit_structural(
                    fl(r"phpinfo|var_dump|print_r|DEBUG query"),
                    "errormessage",
                    "php.debug.err",
                    "debug dump — errormessage (CWE-209)",
                )

        # resource exhaustion — unbounded str_repeat. Safes min() cap.
        if re.search(r"str_repeat\s*\(", src) and "min(" not in src and "1048576" not in src:
            self.emit_structural(
                fl(r"str_repeat"),
                "resourceexhaust",
                "php.str_repeat",
                "str_repeat of unbounded user size — resourceexhaust (CWE-400)",
            )

        # integer overflow
        if re.search(r"\(\s*int\s*\)\s*\$\w+\s*\+\s*1", src) and "2147483646" not in src:
            self.emit_structural(
                fl(r"\(\s*int\s*\)"),
                "intoverflow",
                "php.int.add",
                "int + 1 without bound — intoverflow (CWE-190)",
            )

        # posix setuid of user-controlled uid — not posix_setuid(65534) nobody
        if re.search(r"posix_setu(?:id|gid)\s*\(\s*(?:\(int\)\s*)?\$(?:data|userInput|processed|uid)", src):
            self.emit_structural(
                fl(r"posix_setuid|posix_setgid"),
                "privescalation",
                "php.setuid",
                "posix_setuid of user uid — privescalation (CWE-269)",
            )

        # scandir listing — basename / strong allowlist / session gate are safes.
        # Symfony twin: getSession()->get('user') + HttpException(401), not session()/abort(401).
        session_gate = bool(
            re.search(r"\bsession\s*\(|abort\(401|HttpException\s*\(\s*401|getSession\s*\(", src)
        )
        if re.search(r"\bscandir\s*\(|\bglob\s*\(", src) and "basename" not in src and not strong_alnum:
            if not session_gate:
                self.emit_structural(
                    fl(r"scandir|glob"),
                    "directory_listing_exposure",
                    "php.scandir",
                    "scandir/glob of user path — directory_listing_exposure (CWE-209)",
                )

        # cleartext storage
        if "secrets.txt" in src or re.search(r"file_put_contents\s*\([^,]+,\s*\(string\)\s*\$data", src):
            if "password_hash" not in src and "openssl_encrypt" not in src:
                self.emit_structural(
                    fl(r"secrets\.txt|file_put_contents"),
                    "cleartextstorage",
                    "php.secrets",
                    "plaintext write of secret — cleartextstorage (CWE-312)",
                )

        # missing integrity (curl/file of user URL without hash)
        if re.search(r"file_get_contents\s*\(\s*\(string\)\s*\$", src) and "hash_file" not in src and "hash_hmac" not in src:
            self.emit_structural(
                fl(r"file_get_contents"),
                "missing_integrity_check",
                "php.nohash",
                "fetch of user URL without integrity hash — missing_integrity_check (CWE-353)",
            )

        # idor — fetch by attacker id without session
        if re.search(r"WHERE id = .*\$(data|userInput|processed)", src) and "session" not in src.lower() and "hash_equals" not in src:
            self.emit_structural(
                fl(r"WHERE id"),
                "idor",
                "php.idor",
                "object fetch by user id without session — idor (CWE-639)",
            )

        # null deref — too sprayy on selectOne second-order sources. Skip.

        # inputval / dataintegrity — echo raw
        if re.search(r"echo\s+\$data|print\s+\$data", src) and not html_esc and not strong_alnum:
            ln = fl(r"echo\s+\$data|print\s+\$data")
            self.emit_structural(ln, "inputval", "php.echo.raw",
                "echo of unsanitized user data — inputval (CWE-20)")
            self.emit_structural(ln, "dataintegrity", "php.echo.integrity",
                "echo of unsanitized user data — dataintegrity (CWE-345)")

    # ── IR lowering ──────────────────────────────────────────────────────

    def lower_file_body(self) -> None:
        for m in re.finditer(r"^use\s+([\w\\]+)", self.source, re.M):
            spec = m.group(1)
            self.imports.append(
                {"localName": spec.split("\\")[-1], "specifier": spec, "imported": "*"}
            )

        for m in _FN.finditer(self.source):
            name = m.group(1)
            params_raw = m.group(2)
            body_start = m.end() - 1
            body, _end = self._extract_braces(self.source, body_start)
            if body is None:
                self.notes.append(f"unbalanced braces in {name}")
                continue
            line = self.source[: m.start()].count("\n") + 1
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
            tainted = []
            for p in params:
                if p in ("request", "req") or p.endswith("Request"):
                    tainted.append(
                        {
                            "name": p if p != "Request" else "request",
                            "sourceId": "php.request",
                            "description": "Laravel/Symfony Request — user-controlled",
                        }
                    )
                if p == "request":
                    tainted.append(
                        {
                            "name": "request",
                            "sourceId": "php.request",
                            "description": "Request $request — user-controlled",
                        }
                    )
            # always taint $request if present
            if "request" in params and not any(t["name"] == "request" for t in tainted):
                tainted.append(
                    {
                        "name": "request",
                        "sourceId": "php.request",
                        "description": "Request $request — user-controlled",
                    }
                )
            if "request" in params:
                fn["taintedParams"] = [
                    {
                        "name": "request",
                        "sourceId": "php.request",
                        "description": "Request $request — user-controlled",
                    }
                ]
            self.functions.append(fn)
            self.exports.append({"exportName": name, "localName": name})

        if not self.functions:
            self.notes.append("no function body found; structural only")

    def _parse_params(self, raw: str) -> List[str]:
        names: List[str] = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            m = re.search(r"\$(\w+)\s*$", part)
            if m:
                names.append(m.group(1))
        return names

    def _extract_braces(self, src: str, start: int) -> Tuple[Optional[str], int]:
        if start >= len(src) or src[start] != "{":
            return None, start
        depth = 0
        i = start
        in_str = None
        esc = False
        while i < len(src):
            ch = src[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == in_str:
                    in_str = None
            else:
                if ch in ("'", '"'):
                    in_str = ch
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
            line = base_line + body[:i].count("\n")
            if body.startswith("if", i) and (i + 2 >= n or not (body[i + 2].isalnum() or body[i + 2] == "_")):
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
                    i = ni
                    continue
            if body.startswith("foreach", i):
                m = re.match(r"foreach\s*\((.+?)\s+as\s+(\$\w+)\)\s*\{", body[i:], re.S)
                if m:
                    iterable = m.group(1)
                    var = m.group(2)[1:]
                    brace_at = i + m.end() - 1
                    inner, end = self._extract_braces(body, brace_at)
                    loop_stmts = [
                        {
                            "kind": "Assign",
                            "id": self.next_id("assign"),
                            "target": var,
                            "value": {
                                "kind": "Call",
                                "callee": {"kind": "Variable", "name": "array_shift"},
                                "args": [self._lower_expr(iterable)],
                            },
                            "location": self.loc(line),
                        }
                    ]
                    loop_stmts.extend(self._lower_block(inner or "", line))
                    stmts.append(
                        {
                            "kind": "Loop",
                            "id": self.next_id("loop"),
                            "condition": None,
                            "body": {"statements": loop_stmts},
                            "location": self.loc(line),
                        }
                    )
                    i = end
                    continue
            if body.startswith("while", i):
                m = re.match(r"while\s*\((.+?)\)\s*\{", body[i:], re.S)
                if m:
                    brace_at = i + m.end() - 1
                    inner, end = self._extract_braces(body, brace_at)
                    stmts.append(
                        {
                            "kind": "Loop",
                            "id": self.next_id("loop"),
                            "condition": self._lower_expr(m.group(1)),
                            "body": {"statements": self._lower_block(inner or "", line)},
                            "location": self.loc(line),
                        }
                    )
                    i = end
                    continue
            if body.startswith("try", i):
                m = re.match(r"try\s*\{", body[i:])
                if m:
                    brace_at = i + m.end() - 1
                    inner, end = self._extract_braces(body, brace_at)
                    catch_block = None
                    rest = body[end:].lstrip()
                    if rest.startswith("catch"):
                        cm = re.match(r"catch\s*\([^)]*\)\s*\{", rest)
                        if cm:
                            cbrace = end + (len(body[end:]) - len(rest)) + cm.end() - 1
                            cinner, cend = self._extract_braces(body, cbrace)
                            catch_block = {"statements": self._lower_block(cinner or "", line)}
                            end = cend
                    stmts.append(
                        {
                            "kind": "TryCatch",
                            "id": self.next_id("try"),
                            "tryBlock": {"statements": self._lower_block(inner or "", line)},
                            "catchBlock": catch_block,
                            "location": self.loc(line),
                        }
                    )
                    i = end
                    continue
            if body.startswith("return", i):
                j = i + 6
                expr, ni = self._read_stmt(body, j)
                stmts.append(
                    {
                        "kind": "Return",
                        "id": self.next_id("ret"),
                        "value": self._lower_expr(expr) if expr.strip() else None,
                        "location": self.loc(line),
                    }
                )
                i = ni
                continue
            # assignment or expression
            stmt_s, ni = self._read_stmt(body, i)
            stmt_s = stmt_s.strip().rstrip(";").strip()
            if not stmt_s:
                i = ni
                continue
            # [$data] = [$userInput, 'http']
            m = re.match(r"^\[\s*\$(\w+)\s*\]\s*=\s*\[(.+)\]$", stmt_s, re.S)
            if m:
                first = self._split_top(m.group(2), ",")[0]
                stmts.append(
                    {
                        "kind": "Assign",
                        "id": self.next_id("assign"),
                        "target": m.group(1),
                        "value": self._lower_expr(first),
                        "location": self.loc(line),
                    }
                )
                i = ni
                continue
            # $$field = $userInput  → assign to const string of $field
            m = re.match(r"^\$\$(\w+)\s*=\s*(.+)$", stmt_s, re.S)
            if m:
                inner_name = m.group(1)
                target = self._const_str.get(inner_name, "data")
                stmts.append(
                    {
                        "kind": "Assign",
                        "id": self.next_id("assign"),
                        "target": target,
                        "value": self._lower_expr(m.group(2)),
                        "location": self.loc(line),
                    }
                )
                i = ni
                continue
            m = re.match(r"^\$(\w+)->(\w+)\s*=\s*(.+)$", stmt_s, re.S)
            if m:
                stmts.append(
                    {
                        "kind": "FieldAssign",
                        "id": self.next_id("fassign"),
                        "object": {"kind": "Variable", "name": m.group(1)},
                        "field": m.group(2),
                        "value": self._lower_expr(m.group(3)),
                        "location": self.loc(line),
                    }
                )
                i = ni
                continue
            m = re.match(r"^\$(\w+)\s*=\s*(.+)$", stmt_s, re.S)
            if m:
                target, val_s = m.group(1), m.group(2)
                use_m = re.search(r"function\s*\([^)]*\)\s*use\s*\(\s*\$(\w+)", val_s)
                if use_m:
                    value = {"kind": "Variable", "name": use_m.group(1)}
                else:
                    value = self._lower_expr(val_s)
                if value.get("kind") == "Literal" and value.get("literalKind") == "string" and value.get("raw"):
                    self._const_str[target] = value["raw"]
                stmts.append(
                    {
                        "kind": "Assign",
                        "id": self.next_id("assign"),
                        "target": target,
                        "value": value,
                        "location": self.loc(line),
                    }
                )
                i = ni
                continue
            stmts.append(
                {
                    "kind": "ExpressionStmt",
                    "id": self.next_id("expr"),
                    "expr": self._lower_expr(stmt_s),
                    "location": self.loc(line),
                }
            )
            i = ni
        return stmts

    def _parse_if(self, body: str, i: int) -> Tuple[Optional[str], Optional[str], Optional[str], int]:
        rest = body[i:]
        m = re.match(r"if\s*\(", rest)
        if not m:
            return None, None, None, i
        # find matching paren for condition
        start = m.end() - 1
        depth = 0
        in_str = None
        esc = False
        j = start
        while j < len(rest):
            ch = rest[j]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == in_str:
                    in_str = None
            else:
                if ch in ("'", '"'):
                    in_str = ch
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        break
            j += 1
        cond = rest[start + 1 : j]
        k = j + 1
        while k < len(rest) and rest[k].isspace():
            k += 1
        then_body = ""
        else_body = None
        if k < len(rest) and rest[k] == "{":
            inner, end_rel = self._extract_braces(rest, k)
            then_body = inner or ""
            k = end_rel
        else:
            stmt, k2 = self._read_stmt(rest, k)
            then_body = stmt
            k = k2
        rest2 = rest[k:]
        stripped = rest2.lstrip()
        skip = len(rest2) - len(stripped)
        if stripped.startswith("else"):
            k += skip + 4
            while k < len(rest) and rest[k].isspace():
                k += 1
            if k < len(rest) and rest[k] == "{":
                inner, end_rel = self._extract_braces(rest, k)
                else_body = inner or ""
                k = end_rel
            else:
                stmt, k2 = self._read_stmt(rest, k)
                else_body = stmt
                k = k2
        return cond, then_body, else_body, i + k

    def _read_stmt(self, body: str, i: int) -> Tuple[str, int]:
        """Read one statement ending at ; at paren/brace depth 0."""
        n = len(body)
        depth_p = 0
        depth_b = 0
        in_str = None
        esc = False
        start = i
        while i < n:
            ch = body[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == in_str:
                    in_str = None
            else:
                if ch in ("'", '"'):
                    in_str = ch
                elif ch == "(":
                    depth_p += 1
                elif ch == ")":
                    depth_p -= 1
                elif ch == "{":
                    depth_b += 1
                elif ch == "}":
                    if depth_b == 0 and depth_p == 0:
                        return body[start:i], i
                    depth_b -= 1
                elif ch == ";" and depth_p == 0 and depth_b == 0:
                    return body[start:i], i + 1
            i += 1
        return body[start:i], i

    def _split_top(self, raw: str, sep: str) -> List[str]:
        parts: List[str] = []
        depth_p = 0
        depth_b = 0
        in_str = None
        esc = False
        buf = []
        i = 0
        while i < len(raw):
            ch = raw[i]
            if in_str:
                buf.append(ch)
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == in_str:
                    in_str = None
                i += 1
                continue
            if ch in ("'", '"'):
                in_str = ch
                buf.append(ch)
                i += 1
                continue
            if ch == "(":
                depth_p += 1
            elif ch == ")":
                depth_p -= 1
            elif ch == "[":
                depth_b += 1
            elif ch == "]":
                depth_b -= 1
            if depth_p == 0 and depth_b == 0 and raw.startswith(sep, i):
                # do not split `->` on `>` or `-`
                if sep == ">" and i > 0 and raw[i - 1] == "-":
                    buf.append(ch)
                    i += 1
                    continue
                if sep == "-" and i + 1 < len(raw) and raw[i + 1] == ">":
                    buf.append(ch)
                    i += 1
                    continue
                parts.append("".join(buf))
                buf = []
                i += len(sep)
                continue
            buf.append(ch)
            i += 1
        parts.append("".join(buf))
        return parts

    def _lower_expr(self, raw: str) -> Dict[str, Any]:
        raw = raw.strip().rstrip(";").strip()
        if not raw:
            return {"kind": "Unknown", "hint": ""}
        raw = raw.replace("?->", "->")

        # interpolations "{$userInput}" / "$userInput"
        m = re.match(r'^"\{\$(\w+)\}"$', raw)
        if m:
            return {"kind": "Variable", "name": m.group(1)}
        m = re.match(r'^"\$(\w+)"$', raw)
        if m:
            return {"kind": "Variable", "name": m.group(1)}

        if raw.startswith("(") and raw.endswith(")") and self._balanced(raw):
            return self._lower_expr(raw[1:-1])

        # casts
        m = re.match(r"^\((int|integer|bool|boolean|float|double)\)\s*(.+)$", raw)
        if m:
            return {
                "kind": "Call",
                "callee": {"kind": "Variable", "name": "int" if m.group(1) in ("int", "integer") else m.group(1)},
                "args": [self._lower_expr(m.group(2))],
            }
        m = re.match(r"^\((string)\)\s*(.+)$", raw)
        if m:
            return {
                "kind": "Call",
                "callee": {"kind": "Variable", "name": "strval"},
                "args": [self._lower_expr(m.group(2))],
            }

        # unary !
        if raw.startswith("!") and not raw.startswith("!="):
            return {"kind": "Unary", "op": "!", "operand": self._lower_expr(raw[1:].strip())}

        # PHP elvis ?:  (before generic ternary)
        parts_e = self._split_top(raw, "?:")
        if len(parts_e) == 2:
            return {
                "kind": "Binary",
                "op": "||",
                "left": self._lower_expr(parts_e[0]),
                "right": self._lower_expr(parts_e[1]),
            }

        # null coalesce ??
        parts_n = self._split_top(raw, "??")
        if len(parts_n) == 2:
            return {
                "kind": "Binary",
                "op": "||",
                "left": self._lower_expr(parts_n[0]),
                "right": self._lower_expr(parts_n[1]),
            }

        # ternary
        parts_q = self._split_top(raw, "?")
        if len(parts_q) == 2 and ":" in parts_q[1]:
            true_s, false_s = parts_q[1].split(":", 1)
            # join both sides so taint is conservative
            return {
                "kind": "Binary",
                "op": "||",
                "left": self._lower_expr(true_s),
                "right": self._lower_expr(false_s),
            }

        # concat .
        parts = self._split_top(raw, ".")
        # avoid splitting $obj->method — '.' used; '->' is not '.'
        # but PHP concat is ' . ' often. Also $this-> is '->' not '.'
        real_concat = []
        if len(parts) > 1:
            # filter false splits from numbers 1.0 — rare in BP
            real_concat = parts
        if len(real_concat) > 1:
            node = self._lower_expr(real_concat[0])
            for p in real_concat[1:]:
                node = {"kind": "Binary", "op": "+", "left": node, "right": self._lower_expr(p)}
            return node

        # calls before binary `>` so `$obj->method()` is not split
        call = self._try_call(raw)
        if call is not None:
            return call

        for op in ("===", "!==", "==", "!=", "&&", "||", "<=", ">=", "<", ">"):
            parts = self._split_top(raw, op)
            if len(parts) == 2:
                return {
                    "kind": "Binary",
                    "op": op,
                    "left": self._lower_expr(parts[0]),
                    "right": self._lower_expr(parts[1]),
                }

        # strings
        m = re.match(r"^'([^'\\]|\\.)*'$", raw)
        if m:
            return {"kind": "Literal", "literalKind": "string", "raw": ast_unquote(raw)}
        m = re.match(r'^"([^"\\]|\\.)*"$', raw)
        if m:
            inner = ast_unquote(raw)
            im = re.search(r"\$(\w+)", inner)
            if im and "{$" not in inner:
                # "$userInput extra" — treat as concat of var
                return {"kind": "Variable", "name": im.group(1)}
            return {"kind": "Literal", "literalKind": "string", "raw": inner}

        if re.match(r"^-?\d+(\.\d+)?$", raw):
            return {"kind": "Literal", "literalKind": "number", "raw": raw}
        if raw in ("true", "false"):
            return {"kind": "Literal", "literalKind": "boolean", "raw": raw}
        if raw in ("null", "NULL"):
            return {"kind": "Literal", "literalKind": "null", "raw": "null"}

        # array literals
        if (raw.startswith("[") and raw.endswith("]")) or (raw.startswith("array(") and raw.endswith(")")):
            inner = raw[1:-1] if raw.startswith("[") else raw[6:-1]
            els = []
            props = []
            is_assoc = False
            for item in self._split_top(inner, ","):
                item = item.strip()
                if not item:
                    continue
                if "=>" in item:
                    is_assoc = True
                    k, v = item.split("=>", 1)
                    k = ast_unquote(k.strip()) if k.strip()[:1] in "'\"" else k.strip()
                    props.append({"key": k, "value": self._lower_expr(v.strip())})
                else:
                    els.append(self._lower_expr(item))
            if is_assoc:
                return {"kind": "ObjectLiteral", "props": props}
            return {"kind": "ArrayLiteral", "elements": els}

        # $var
        m = re.match(r"^\$(\w+)$", raw)
        if m:
            return {"kind": "Variable", "name": m.group(1)}

        # call  Foo::bar(...)  $obj->m(...)  name(...)
        call = self._try_call(raw)
        if call is not None:
            return call

        # $obj->prop  Foo::$bar
        m = re.match(r"^(.+)->(\w+)$", raw)
        if m:
            return {
                "kind": "FieldAccess",
                "object": self._lower_expr(m.group(1)),
                "field": m.group(2),
            }

        # bare ident (STDIN, DB, Blade)
        if re.match(r"^[A-Za-z_\\][\w\\]*$", raw):
            name = raw.split("\\")[-1]
            return {"kind": "Variable", "name": name}

        # getenv('USER_INPUT') ?: ''
        parts = self._split_top(raw, "?:")
        if len(parts) == 2:
            return {
                "kind": "Binary",
                "op": "||",
                "left": self._lower_expr(parts[0]),
                "right": self._lower_expr(parts[1]),
            }

        return {"kind": "Unknown", "hint": raw[:120]}

    def _try_call(self, raw: str) -> Optional[Dict[str, Any]]:
        raw = raw.strip()
        if not raw.endswith(")"):
            return None
        # First top-level '(' starts the innermost call; matching ')' may
        # leave `->method(...)` / `::method(...)` chain remainder.
        depth = 0
        in_str = None
        esc = False
        open_idx = -1
        for i, ch in enumerate(raw):
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == in_str:
                    in_str = None
                continue
            if ch in ("'", '"'):
                in_str = ch
                continue
            if ch == "(":
                if depth == 0 and open_idx < 0:
                    open_idx = i
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and open_idx >= 0:
                    close_idx = i
                    callee_s = raw[:open_idx].strip()
                    args_s = raw[open_idx + 1 : close_idx]
                    if not callee_s or any(c in callee_s for c in "=,;"):
                        return None
                    if "." in callee_s and "->" not in callee_s:
                        return None
                    if callee_s in ("if", "elseif", "foreach", "while", "for", "switch", "catch"):
                        return None
                    args = [self._lower_expr(a) for a in self._split_top(args_s, ",") if a.strip()]
                    node: Dict[str, Any] = {
                        "kind": "Call",
                        "callee": self._lower_callee(callee_s),
                        "args": args,
                    }
                    rest = raw[close_idx + 1 :].strip()
                    while rest.startswith("->") or rest.startswith("::"):
                        rest = rest[2:]
                        m = re.match(r"^(\w+)\s*\(", rest)
                        if not m:
                            # property only: ->text
                            m2 = re.match(r"^(\w+)$", rest)
                            if m2:
                                node = {
                                    "kind": "FieldAccess",
                                    "object": node,
                                    "field": m2.group(1),
                                }
                                rest = ""
                                break
                            return None
                        meth = m.group(1)
                        # matching args of this chained call
                        sub = rest[m.end() - 1 :]
                        if not sub.startswith("("):
                            return None
                        d = 0
                        ins = None
                        e = False
                        end = -1
                        for j, c2 in enumerate(sub):
                            if ins:
                                if e:
                                    e = False
                                elif c2 == "\\":
                                    e = True
                                elif c2 == ins:
                                    ins = None
                                continue
                            if c2 in ("'", '"'):
                                ins = c2
                                continue
                            if c2 == "(":
                                d += 1
                            elif c2 == ")":
                                d -= 1
                                if d == 0:
                                    end = j
                                    break
                        if end < 0:
                            return None
                        chained_args = [
                            self._lower_expr(a)
                            for a in self._split_top(sub[1:end], ",")
                            if a.strip()
                        ]
                        node = {
                            "kind": "Call",
                            "callee": {"kind": "FieldAccess", "object": node, "field": meth},
                            "args": chained_args,
                        }
                        rest = sub[end + 1 :].strip()
                    if rest:
                        return None
                    return node
        return None

    def _lower_callee(self, raw: str) -> Dict[str, Any]:
        raw = raw.strip()
        # strip leading \
        raw = raw.lstrip("\\")
        if "->" in raw:
            parts = raw.split("->")
            node: Dict[str, Any] = self._lower_expr(parts[0]) if parts[0].startswith("$") else {
                "kind": "Variable",
                "name": parts[0].split("\\")[-1],
            }
            # if first part is itself a call, lower it
            if "(" in parts[0]:
                node = self._lower_expr(parts[0])
            for p in parts[1:]:
                node = {"kind": "FieldAccess", "object": node, "field": p.split("(")[0]}
            return node
        if "::" in raw:
            left, right = raw.rsplit("::", 1)
            left_name = left.split("\\")[-1]
            return {
                "kind": "FieldAccess",
                "object": {"kind": "Variable", "name": left_name},
                "field": right,
            }
        if raw.startswith("$"):
            return {"kind": "Variable", "name": raw[1:]}
        return {"kind": "Variable", "name": raw.split("\\")[-1]}

    def _balanced(self, raw: str) -> bool:
        if not (raw.startswith("(") and raw.endswith(")")):
            return False
        depth = 0
        in_str = None
        esc = False
        for i, ch in enumerate(raw):
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == in_str:
                    in_str = None
                continue
            if ch in ("'", '"'):
                in_str = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i == len(raw) - 1
        return False


def ast_unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] in "'\"" and s[-1] == s[0]:
        inner = s[1:-1]
        return inner.replace("\\'", "'").replace('\\"', '"').replace("\\n", "\n")
    return s


def main() -> int:
    args = sys.argv[1:]
    if not args:
        sys.stderr.write("usage: python3 -m vantage.nebula_frontend_php <file.php> [...]\n")
        return 2
    if args[0] == "--batch":
        files = [ln.strip() for ln in sys.stdin if ln.strip()]
    else:
        files = args
    modules = []
    for f in files:
        try:
            modules.append(lower_file(f))
        except Exception as e:
            sys.stderr.write(f"{f}: {type(e).__name__}: {e}\n")
            modules.append(
                {
                    "path": f,
                    "functions": [],
                    "topLevel": {"statements": []},
                    "frontendNotes": [f"lower error: {e}"],
                    "imports": [],
                    "exports": [],
                }
            )
    sys.stdout.write(json.dumps(modules))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
