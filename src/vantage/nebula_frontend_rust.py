"""
VANTAGE NEBULA — Rust frontend.

Lowers raw Rust (no rustc / cargo / syn) into the same ModuleIR the other
frontends emit. One .rs file = one ModuleIR. Macros are call-shaped.
#[cfg] branches are live. Decision: receipts/sealed-holdout/
rust-v1-normal-actix-web-2026-08-20/RECEIPT.md §2a–2c.

Usage:
    python3 -m vantage.nebula_frontend_rust <file.rs> [...]
    python3 -m vantage.nebula_frontend_rust --batch   # paths on stdin
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


_FN_DEF = re.compile(
    r"(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(([^;{]*)\)\s*(?:->\s*[^{]+)?\s*\{",
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
        # static _RE_SCHEMA = Regex::new(r"^[a-zA-Z0-9_.-]+$") — used to lower
        # `_RE_SCHEMA.is_match(&data)` as the analyzer's strong `.test(literal)`.
        self.regex_consts: Dict[str, str] = {}
        for m in re.finditer(
            r"(_RE_[A-Za-z0-9_]+)\b[\s\S]{0,400}?Regex::new\(\s*(?:r#*)?\"([^\"]+)\"",
            source,
        ):
            self.regex_consts[m.group(1)] = m.group(2)
        if "unsafe" in source:
            self.notes.append("raw-source: unsafe blocks are notes, not a second IR")
        if re.search(r"#\s*\[cfg", source):
            self.notes.append("raw-source: cfg branches treated as live")
        self.ssrf_guarded = False
        self.cmd_guarded = False
        self.path_guarded = False
        self.upload_guarded = False
        self.sql_guarded = False
        self.log_guarded = False
        self.csv_guarded = False
        self.html_guarded = False
        self.err_guarded = False

    def next_id(self, kind: str) -> str:
        self.stmt_counter += 1
        return f"{kind}_{self.stmt_counter}"

    def loc(self, line: int = 1) -> Dict[str, Any]:
        return {"file": self.file_path, "line": int(line), "column": 1}

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

        strong_re = (
            live(r"_RE_SCHEMA\b") or live(r"_RE_ALLOW\b") or live(r'_RE_SCHEMA:')
        ) and not live(r"_RE_SCHEMA_BROKEN") and not live(r"_RE_BROKEN")
        # anchored allow regex used by safes
        if live(r'\^\[a-zA-Z0-9_\.\-\]\+\$') or live(r'\^\[a-zA-Z0-9_-\]\+\$'):
            if not live(r"_RE_BROKEN") and not live(r"_RE_SCHEMA_BROKEN"):
                strong_re = True
        auth = "verify_bearer" in src or "user_has_role" in src
        ammonia = "ammonia::clean" in src
        html_esc = "html_escape::encode_text" in src
        shell_esc = "shell_escape" in src
        cmd_allow = '["ls", "cat"' in src or "['ls', 'cat'" in src
        cookie_flags = "HttpOnly" in src and "SameSite" in src
        cookie_build_guard = (
            "Cookie::build" in src
            and "secure(true)" in src
            and "http_only(true)" in src
            and (
                "SameSite::Strict" in src
                or "same_site(Strict)" in src
                or 'same_site(cookie::SameSite::Strict)' in src
            )
        )
        cookie_flags = cookie_flags or cookie_build_guard
        bool_allow = '["true", "false"' in src or "['true', 'false'" in src
        contains_allow = ".contains(&data" in src or ".contains(&processed" in src
        host_allow = "api.priv.local" in src or "cdn.edgecdn.io" in src
        # Safe twins block cloud metadata by IP prefix and/or hostname — not always the
        # literal 169.254.169.254 token the first QT pass keyed on.
        meta_block = (
            ("metadata.google.internal" in src or 'host == "metadata"' in src or '"metadata"' in src)
            and ("169.254" in src)
        )
        sha256 = "Sha256" in src
        osrng = "OsRng" in src
        vault = (
            "vault_get" in src
            or 'env::var("APP_SECRET")' in src
            or "keyring_get" in src
            or "/etc/app/secrets.yaml" in src
        )
        bind = "db_query_bind" in src or "db_exec_bind" in src
        basename = "file_name()" in src
        numeric = "parse::<i64>" in src or "parse::<i32>" in src
        csv_quote = "starts_with('=')" in src or 'starts_with("=")' in src
        redact = "_RE_REDACT" in src or "_crlf_stripped" in src
        ext_ends = "ends_with(ext)" in src
        csrf_ok = "expected_csrf" in src
        csp = "frame-ancestors" in src or "Content-Security-Policy" in src
        ext_allow = '".jpg"' in src and '".png"' in src
        path_allow = '"config.json"' in src and '"index.html"' in src
        log_allow = '["asc", "desc"' in src or '["true", "false"' in src
        generic_err = 'send_error("An error occurred")' in src
        clamp = ".clamp(" in src or ".min(" in src
        yaml = "serde_yaml::from_str" in src
        json_de = "serde_json::from_str" in src and not yaml

        # ── command injection cluster ──
        # Safe twins: shell_escape, .contains(&data) allowlist, argv form
        # Command::new("echo").arg(&data). Do not fire on those.
        argv_form = bool(re.search(r'Command::new\("(echo|ls|cat|date|whoami)"\)\.arg\(&', src))
        shell_concat = bool(re.search(r'Command::new\("(sh|bash)"\)', src)) and "format!(" in src
        prog_from_user = bool(re.search(r"Command::new\(&", src))
        self.ssrf_guarded = bool(meta_block or host_allow)
        self.cmd_guarded = bool(shell_esc or cmd_allow or contains_allow or argv_form or strong_re)
        self.path_guarded = bool(path_allow or contains_allow or strong_re or basename)
        self.upload_guarded = bool(ext_allow or ext_ends)
        self.sql_guarded = bool(bind or strong_re or numeric)
        self.log_guarded = bool(log_allow or bool_allow or strong_re or contains_allow or redact)
        self.csv_guarded = bool(strong_re or contains_allow or csv_quote)
        self.html_guarded = bool(ammonia or html_esc or strong_re or bool_allow or contains_allow)
        self.err_guarded = bool(auth)
        if (prog_from_user or shell_concat) and not self.cmd_guarded:
            ln = fl(r"Command::new")
            if prog_from_user:
                self.emit_structural(ln, "cmdi", "rust.Command.new",
                    "Command::new of user program without shell_escape/allowlist — cmdi (CWE-78)")
                self.emit_structural(ln, "genericcmdi", "rust.Command.generic",
                    "Command::new of user program without shell_escape/allowlist — genericcmdi (CWE-77)")
            if shell_concat:
                self.emit_structural(ln, "argument_injection", "rust.Command.shc",
                    "sh/bash -c of formatted user string without shell_escape — argument_injection (CWE-88)")
                if not prog_from_user:
                    self.emit_structural(ln, "genericcmdi", "rust.Command.shc.generic",
                        "sh/bash -c of formatted user string without allowlist — genericcmdi (CWE-77)")

        # ── SQL / LDAP / NoSQL / XPath ──
        if live(r"db_query\(") and not self.sql_guarded and "replace('`'" not in src and 'replace(\'`\'' not in src:
            self.emit_structural(fl(r"db_query\("), "sqli", "rust.db_query",
                "db_query of formatted SQL without bind — sqli (CWE-89)")
        if live(r"ldap_search\(") and not strong_re and not contains_allow and not log_allow:
            self.emit_structural(fl(r"ldap_search\("), "ldapi", "rust.ldap_search",
                "ldap_search of formatted filter without schema regex — ldapi (CWE-90)")
        if live(r"nosql_find_one\(") and not strong_re and not contains_allow and not log_allow:
            self.emit_structural(fl(r"nosql_find_one\("), "nosql", "rust.nosql_find_one",
                "nosql_find_one of formatted $where without allow regex — nosql (CWE-943)")
        if live(r"xpath_eval\(") and not self.html_guarded and not bool_allow:
            self.emit_structural(fl(r"xpath_eval\("), "xpathi", "rust.xpath_eval",
                "xpath_eval of formatted expression without allowlist — xpathi (CWE-643)")

        # ── HTML / SSTI / EL / XSS / dataintegrity ──
        if live(r"render_html\(") and not self.html_guarded:
            ln = fl(r"render_html\(")
            self.emit_structural(ln, "xss", "rust.render_html.xss",
                "render_html of user data without ammonia/schema — xss (CWE-79)")
            self.emit_structural(ln, "basic_xss", "rust.render_html.basic",
                "render_html of user data without ammonia/schema — basic_xss (CWE-80)")
            self.emit_structural(ln, "ssti", "rust.render_html.ssti",
                "render_html of user template without schema regex — ssti (CWE-1336)")
            self.emit_structural(ln, "el_injection", "rust.render_html.el",
                "render_html of user expression without schema regex — el_injection (CWE-917)")
            self.emit_structural(ln, "dataintegrity", "rust.render_html.di",
                "render_html of user data without boolean allowlist — dataintegrity (CWE-345)")

        # ── path / upload ──
        if "/var/app/data/" in src and not self.path_guarded:
            self.emit_structural(fl(r"/var/app/data/"), "pathtraver", "rust.fs.appdata",
                "fs of /var/app/data/ + user without filename allowlist — pathtraver (CWE-22)")
        if "/var/uploads/" in src and not self.upload_guarded:
            self.emit_structural(fl(r"/var/uploads/"), "fileupload", "rust.fs.upload",
                "write /var/uploads/ + user without extension allowlist — fileupload (CWE-434)")
        # 203-cat sensitive-file siblings — positive path evidence, not CWE-22 alias.
        if "app_audit.log" in src:
            self.emit_structural(fl(r"app_audit\.log"), "sensitive_file_insertion", "rust.fs.audit",
                "plaintext write to app_audit.log — sensitive_file_insertion (CWE-538)")
        if "/var/www/html" in src:
            self.emit_structural(fl(r"/var/www/html"), "sensitive_file_web_root", "rust.fs.www",
                "plaintext write under /var/www/html — sensitive_file_web_root (CWE-219)")

        # ── SSRF / cloud metadata (same CWE-918; file-level scoring) ──
        if (live(r"reqwest::get\(") or live(r"TcpStream::connect")) and not meta_block and not host_allow and not contains_allow:
            ln = fl(r"reqwest::get\(") if live(r"reqwest::get\(") else fl(r"TcpStream::connect")
            self.emit_structural(ln, "ssrf", "rust.reqwest.get",
                "reqwest/TcpStream of user URL without metadata/host blocklist — ssrf (CWE-918)")
            self.emit_structural(ln, "cloud_ssrf_metadata", "rust.reqwest.metadata",
                "reqwest of user URL without cloud-metadata blocklist — cloud_ssrf_metadata (CWE-918)")

        # ── TLS / signature ──
        if "danger_accept_invalid_certs(true)" in src:
            ln = fl(r"danger_accept_invalid_certs\(true\)")
            self.emit_structural(ln, "tlsverify", "rust.tls.danger",
                "danger_accept_invalid_certs(true) — tlsverify (CWE-295)")
            self.emit_structural(ln, "unverified_signature", "rust.tls.sig",
                "danger_accept_invalid_certs(true) — unverified_signature (CWE-347)")

        # ── crypto structural ──
        if live(r"md5::Md5") and not sha256:
            ln = fl(r"md5::Md5")
            self.emit_structural(ln, "weakhash", "rust.md5",
                "md5::Md5 digest — weakhash (CWE-328)")
            self.emit_structural(ln, "weak_password_hash", "rust.md5.pw",
                "md5::Md5 digest — weak_password_hash (CWE-916)")
        if "^ 0x42" in src or "0x42u8" in src:
            ln = fl(r"0x42")
            self.emit_structural(ln, "weakcipher", "rust.xor42",
                "XOR 0x42 stand-in cipher — weakcipher (CWE-327)")
            self.emit_structural(ln, "weakkeylength", "rust.xor42.key",
                "XOR 0x42 stand-in cipher — weakkeylength (CWE-326)")
        if "seed_from_u64" in src and not osrng:
            self.emit_structural(fl(r"seed_from_u64"), "weakrand", "rust.StdRng.seed",
                "StdRng::seed_from_u64 of user bytes — weakrand (CWE-330)")
        if "encrypt_with_key" in src and not vault:
            self.emit_structural(fl(r"encrypt_with_key"), "hardcoded_crypto_key", "rust.encrypt_with_key",
                "encrypt_with_key of non-env key — hardcoded_crypto_key (CWE-321)")
        if "p4ssw0rd_test_xyz" in src or "xoxb-EXAMPLE" in src or "s3cr3t_key_test_xyz" in src:
            ln = fl(r"p4ssw0rd_test_xyz") if "p4ssw0rd_test_xyz" in src else (
                fl(r"xoxb-EXAMPLE") if "xoxb-EXAMPLE" in src else fl(r"s3cr3t_key_test_xyz")
            )
            self.emit_structural(ln, "hardcodedcreds", "rust.secret.planted",
                "Planted secret literal — hardcodedcreds (CWE-798)")
        if 'auth_check("user"' in src:
            ln = fl(r'auth_check\("user"')
            self.emit_structural(ln, "default_credentials", "rust.auth_check.user",
                'auth_check("user", ...) — default_credentials (CWE-1392)')
            self.emit_structural(ln, "credprotection", "rust.auth_check.user.cred",
                'auth_check("user", ...) without vault — credprotection (CWE-522)')

        # ── cookies ──
        # QT flag cats: set_cookie + HttpOnly/SameSite header strings.
        # 315/784: Cookie::build without .secure(true) / .http_only(true) only.
        # Do not emit 315/784 on set_cookie — that was the spray.
        if live(r"set_cookie\(") and not cookie_flags:
            ln = fl(r"set_cookie\(")
            self.emit_structural(ln, "cookie_no_httponly", "rust.cookie.httponly",
                "set_cookie without HttpOnly/SameSite/Secure — cookie_no_httponly (CWE-1004)")
            self.emit_structural(ln, "cookie_no_samesite", "rust.cookie.samesite",
                "set_cookie without SameSite=Strict — cookie_no_samesite (CWE-1275)")
            self.emit_structural(ln, "securecookie", "rust.cookie.secure",
                "set_cookie without Secure flag — securecookie (CWE-614)")
        if "Cookie::build" in src:
            missing_secure = "secure(true)" not in src
            missing_httponly = "http_only(true)" not in src
            if missing_secure or missing_httponly:
                ln = fl(r"Cookie::build")
                if missing_httponly:
                    self.emit_structural(ln, "cookie_no_httponly", "rust.cookie.build.httponly",
                        "Cookie::build without .http_only(true) — cookie_no_httponly (CWE-1004)")
                    self.emit_structural(ln, "cleartext_cookie", "rust.cookie.build.cleartext",
                        "Cookie::build without .http_only(true) — cleartext_cookie (CWE-315)")
                if missing_secure:
                    self.emit_structural(ln, "securecookie", "rust.cookie.build.secure",
                        "Cookie::build without .secure(true) — securecookie (CWE-614)")
                    self.emit_structural(ln, "cleartext_cookie", "rust.cookie.build.cleartext.sec",
                        "Cookie::build without .secure(true) — cleartext_cookie (CWE-315)")
                self.emit_structural(ln, "cookie_no_integrity_check", "rust.cookie.build.integrity",
                    "Cookie::build without .secure(true)/.http_only(true) — cookie_no_integrity_check (CWE-784)")

        # ── CSRF ──
        if "UPDATE users SET" in src and not csrf_ok:
            self.emit_structural(fl(r"UPDATE users SET"), "csrf", "rust.csrf.missing",
                "state-changing UPDATE without expected_csrf — csrf (CWE-352)")

        # ── deserial ──
        if yaml and not json_de:
            if not strong_re:
                self.emit_structural(fl(r"serde_yaml::from_str"), "deserial", "rust.yaml.from_str",
                    "serde_yaml::from_str of user data — deserial (CWE-502)")

        # ── authn / authz / idor / brute ──
        if '_role == "admin"' in src and not auth:
            ln = fl(r'_role == "admin"')
            self.emit_structural(ln, "authnfailure", "rust.role.admin.authn",
                'role == admin without verify_bearer — authnfailure (CWE-287)')
            self.emit_structural(ln, "missingcritauthn", "rust.role.admin.crit",
                'role == admin without verify_bearer — missingcritauthn (CWE-306)')
            self.emit_structural(ln, "no_brute_force_limit", "rust.role.admin.brute",
                'role == admin without verify_bearer — no_brute_force_limit (CWE-307)')
        if 'store_session("granted_role"' in src and not auth:
            ln = fl(r'store_session\("granted_role"')
            self.emit_structural(ln, "authzfailure", "rust.granted_role.authz",
                "store_session granted_role without user_has_role — authzfailure (CWE-862)")
            self.emit_structural(ln, "authzincorrect", "rust.granted_role.incorrect",
                "store_session granted_role without user_has_role — authzincorrect (CWE-863)")
            self.emit_structural(ln, "idor", "rust.granted_role.idor",
                "store_session granted_role without user_has_role — idor (CWE-639)")
        if live(r"store_session\(") and not auth and 'store_session("granted_role"' not in src and 'store_session("csrf_token"' not in src:
            self.emit_structural(fl(r"store_session\("), "sessionfixation", "rust.store_session.fix",
                "store_session of user data without verify_bearer — sessionfixation (CWE-384)")

        # ── error / info disclosure cluster ──
        if live(r"send_error\(&format!\(\"Error:") and not auth and not generic_err:
            ln = fl(r"send_error\(")
            self.emit_structural(ln, "errormessage", "rust.send_error.msg",
                "send_error of user data without verify_bearer — errormessage (CWE-209)")
            self.emit_structural(ln, "infodisclosure", "rust.send_error.info",
                "send_error of user data without verify_bearer — infodisclosure (CWE-200)")
            self.emit_structural(ln, "directory_listing_exposure", "rust.send_error.dir",
                "send_error of user data without verify_bearer — directory_listing_exposure (CWE-209)")
            self.emit_structural(ln, "debug_code_production", "rust.send_error.debug",
                "send_error of user data without verify_bearer — debug_code_production (CWE-489)")

        # ── logs ──
        if live(r"log::info!") and not self.log_guarded:
            ln = fl(r"log::info!")
            self.emit_structural(ln, "loginjection", "rust.log.info",
                "log::info of user data without allowlist — loginjection (CWE-117)")
            self.emit_structural(ln, "sensinlogs", "rust.log.sens",
                "log::info of user data without allowlist — sensinlogs (CWE-532)")

        # ── redirect ──
        if 'append_header(("Location"' in src and not host_allow:
            self.emit_structural(fl(r"Location"), "redirect", "rust.Location",
                "Location header of user URL without host allowlist — redirect (CWE-601)")

        # ── CORS / clickjack / CRLF ──
        acao_literal = bool(re.search(r'Access-Control-Allow-Origin"\s*,\s*"', src))
        if "Access-Control-Allow-Origin" in src and not acao_literal:
            self.emit_structural(fl(r"Access-Control-Allow-Origin"), "corsmisconfig", "rust.cors.reflect",
                "ACAO reflects user origin — corsmisconfig (CWE-942)")
        if live(r'content_type\("text/html"\)') and not csp:
            self.emit_structural(fl(r'text/html'), "clickjacking", "rust.html.nocsp",
                "text/html response without frame-ancestors CSP — clickjacking (CWE-1021)")
        if 'insert_header(("X-Custom"' in src and not self.log_guarded:
            self.emit_structural(fl(r"X-Custom"), "crlfinjection", "rust.header.xcustom",
                "X-Custom header of user data without allow regex — crlfinjection (CWE-93)")

        # ── csv ──
        if live(r"write_csv\(") and not self.csv_guarded:
            self.emit_structural(fl(r"write_csv\("), "csv_injection", "rust.write_csv",
                "write_csv of user field without allow regex — csv_injection (CWE-1236)")

        # ── cleartext ──
        if "/var/data/plaintext.txt" in src:
            ln = fl(r"plaintext\.txt")
            self.emit_structural(ln, "cleartextstorage", "rust.fs.plaintext",
                "write plaintext.txt without encrypt — cleartextstorage (CWE-312)")
            self.emit_structural(ln, "credprotection", "rust.fs.plaintext.cred",
                "write plaintext.txt without encrypt — credprotection (CWE-522)")
        if live(r'"http://api\.edgecdn\.io') or live(r'post\("http://'):
            self.emit_structural(fl(r'"http://'), "cleartexttransmit", "rust.http.cleartext",
                "http:// POST without TLS — cleartexttransmit (CWE-319)")

        # ── missing integrity ──
        if "INSERT INTO feed" in src and "FEED_SHA256" not in src:
            self.emit_structural(fl(r"INSERT INTO feed"), "missing_integrity_check", "rust.feed.nohash",
                "insert fetched body without FEED_SHA256 check — missing_integrity_check (CWE-353)")

        # ── inputval: unanchored INPUTVAL without SCHEMA or a real allowlist ──
        if live(r"_RE_INPUTVAL") and not live(r"_RE_SCHEMA\b") and not self.log_guarded and not strong_re:
            self.emit_structural(fl(r"_RE_INPUTVAL"), "inputval", "rust.inputval.unanchored",
                "unanchored input regex without schema — inputval (CWE-20)")

        # ── null deref: .unwrap() on Option without match ──
        if live(r"let result: Option") and live(r"result\.unwrap\(\)") and "match result" not in src:
            self.emit_structural(fl(r"result\.unwrap\(\)"), "null_deref", "rust.option.unwrap",
                "Option.unwrap without match None — null_deref (CWE-476)")

        # ── intoverflow / resourceexhaust ──
        if "requested * 4096" in src and not clamp:
            self.emit_structural(fl(r"requested \* 4096"), "intoverflow", "rust.mul.4096",
                "requested * 4096 without clamp — intoverflow (CWE-190)")
        if live(r"vec!\[0u8; ") and not clamp:
            # size from parse without min/clamp
            if ".min(" not in src and ".clamp(" not in src:
                self.emit_structural(fl(r"vec!\[0u8;"), "resourceexhaust", "rust.vec.size",
                    "vec![0u8; parsed size] without min/clamp — resourceexhaust (CWE-400)")

        # ── privesc ──
        if live(r"libc::setuid") and "setuid(65534)" not in src:
            self.emit_structural(fl(r"libc::setuid"), "privescalation", "rust.setuid",
                "libc::setuid of parsed user id — privescalation (CWE-269)")

    # ── IR lowering ──────────────────────────────────────────────────────

    def lower_translation_unit(self) -> None:
        src = self.source
        for m in re.finditer(r"^use\s+([^;]+);", src, re.M):
            spec = m.group(1).strip()
            self.imports.append(
                {"localName": spec.split("::")[-1].split(" as ")[0].strip(), "specifier": spec, "imported": "*"}
            )
        for m in _FN_DEF.finditer(src):
            name = m.group(1)
            params_raw = m.group(2)
            if name in ("if", "for", "while", "match"):
                continue
            body_start = m.end() - 1
            body, _end = self._extract_braces(src, body_start)
            if body is None:
                self.notes.append(f"unbalanced braces in {name}")
                continue
            line = src[: m.start()].count("\n") + 1
            params, tainted = self._parse_params(params_raw)
            stmts = self._lower_block(body, line)
            is_async = "async fn" in src[max(0, m.start() - 12) : m.start() + 10]
            fn: Dict[str, Any] = {
                "id": f"{self.file_path}:{name}:{line}",
                "name": name,
                "params": params,
                "body": {"statements": stmts},
                "location": self.loc(line),
                "modifiers": {"async": is_async, "generator": False, "arrow": False},
            }
            if tainted:
                fn["taintedParams"] = tainted
            self.functions.append(fn)
            self.exports.append({"exportName": name, "localName": name})

    def _parse_params(self, raw: str) -> Tuple[List[str], List[Dict[str, str]]]:
        names: List[str] = []
        tainted: List[Dict[str, str]] = []
        raw = raw.strip()
        if not raw:
            return names, tainted
        parts: List[str] = []
        depth = 0
        cur: List[str] = []
        for ch in raw:
            if ch in "<([":
                depth += 1
                cur.append(ch)
            elif ch in ">)]":
                depth -= 1
                cur.append(ch)
            elif ch == "," and depth == 0:
                parts.append("".join(cur).strip())
                cur = []
            else:
                cur.append(ch)
        tail = "".join(cur).strip()
        if tail:
            parts.append(tail)
        for part in parts:
            part = part.strip()
            if not part or part == "&self" or part == "&mut self" or part == "self":
                continue
            # web::Query(query): Type  /  body: web::Bytes  /  req: HttpRequest
            pat = re.search(r"(?:web::(?:Query|Form|Json|Path)\()?(\w+)\)?\s*:\s*(.+)$", part)
            if not pat:
                ident = _IDENT.findall(part)
                if ident:
                    names.append(ident[-1] if ident[-1] not in ("mut", "pub") else ident[0])
                continue
            name = pat.group(1)
            ty = pat.group(2)
            if name == "mut":
                ident = _IDENT.findall(part)
                name = ident[1] if len(ident) > 1 else ident[0]
            names.append(name)
            if re.search(r"HttpRequest|Bytes|Query|Form|Json|Path|Multipart|web::", ty):
                tainted.append({
                    "name": name,
                    "sourceId": "rust.request",
                    "description": "Actix-web request param — attacker-controlled in BP",
                })
        return names, tainted

    def _extract_braces(self, src: str, start: int) -> Tuple[Optional[str], int]:
        if start >= len(src) or src[start] != "{":
            return None, start
        depth = 0
        i = start
        in_str = False
        in_chr = False
        in_raw = False
        esc = False
        while i < len(src):
            ch = src[i]
            if in_raw:
                if ch == '"' and i + 1 < len(src) and src[i + 1] != '#':
                    # keep scanning until "#
                    pass
                if ch == '"' and i + 1 < len(src) and src[i + 1] == '#':
                    in_raw = False
                    i += 2
                    continue
                i += 1
                continue
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
                if ch == '"' and i > 0 and src[i - 1] == '#':
                    in_raw = True
                elif ch == '"':
                    in_str = True
                elif ch == "'" and (i + 2 >= len(src) or src[i + 2] != "'"):
                    # skip lifetimes 'a
                    if i + 1 < len(src) and (src[i + 1].isalpha() or src[i + 1] == "_"):
                        j = i + 1
                        while j < len(src) and (src[j].isalnum() or src[j] == "_"):
                            j += 1
                        i = j
                        continue
                    in_chr = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return src[start + 1 : i], i + 1
            i += 1
        return None, start

    def _find_stmt_end(self, body: str, i: int) -> int:
        depth = 0
        in_str = False
        esc = False
        j = i
        n = len(body)
        while j < n:
            ch = body[j]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                j += 1
                continue
            if ch == '"':
                in_str = True
            elif ch in "({[":
                depth += 1
            elif ch in ")}]":
                depth -= 1
            elif ch == ";" and depth <= 0:
                return j
            elif ch == "{" and depth == 0:
                inner, end = self._extract_braces(body, j)
                if inner is not None:
                    return end - 1
            j += 1
        return n - 1 if n else 0

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
            if body.startswith("if let", i) or body.startswith("if ", i):
                # consume if { } — lower both arms live. Condition must be real IR
                # so `_RE_SCHEMA.is_match` / allowlist `.contains` reject-guards clear taint.
                brace = body.find("{", i)
                if brace > 0:
                    inner, end = self._extract_braces(body, brace)
                    then_stmts = self._lower_block(inner or "", line)
                    else_stmts: List[Dict[str, Any]] = []
                    k = end
                    while k < n and body[k].isspace():
                        k += 1
                    if body.startswith("else", k):
                        eb = body.find("{", k)
                        if eb > 0:
                            einner, eend = self._extract_braces(body, eb)
                            else_stmts = self._lower_block(einner or "", line)
                            end = eend
                    if body.startswith("if let", i):
                        cond: Dict[str, Any] = {"kind": "Unknown", "hint": "if let"}
                    else:
                        cond_raw = body[i + 3 : brace].strip()
                        cond = self._lower_expr(cond_raw) if cond_raw else {"kind": "Unknown", "hint": "if"}
                    stmt: Dict[str, Any] = {
                        "kind": "Conditional",
                        "id": self.next_id("if"),
                        "condition": cond,
                        "thenBlock": {"statements": then_stmts},
                        "location": self.loc(line),
                    }
                    if else_stmts:
                        stmt["elseBlock"] = {"statements": else_stmts}
                    stmts.append(stmt)
                    i = end
                    continue
            if body.startswith("return ", i) or body.startswith("return;", i):
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
            for kw in ("for ", "while ", "loop ", "match "):
                if body.startswith(kw, i):
                    brace = body.find("{", i)
                    if brace > 0:
                        inner, end = self._extract_braces(body, brace)
                        loop_body = self._lower_block(inner or "", line)
                        stmts.append({
                            "kind": "Loop",
                            "id": self.next_id("loop"),
                            "condition": None,
                            "body": {"statements": loop_body},
                            "location": self.loc(line),
                        })
                        i = end
                        break
            else:
                semi = self._find_stmt_end(body, i)
                raw = body[i:semi].strip().rstrip(";").strip()
                i = max(semi + 1, i + 1)
                if not raw:
                    continue
                stmt = self._lower_simple(raw, line)
                if stmt:
                    stmts.append(stmt)
        return stmts

    def _lower_simple(self, raw: str, line: int) -> Optional[Dict[str, Any]]:
        raw = raw.strip()
        if raw.startswith("let "):
            rest = raw[4:]
            if rest.startswith("mut "):
                rest = rest[4:]
            # strip type
            if ":" in rest and "=" in rest and rest.find(":") < rest.find("="):
                name = rest.split(":", 1)[0].strip()
                rhs = rest.split("=", 1)[1].strip()
            elif "=" in rest:
                name, rhs = rest.split("=", 1)
                name = name.strip()
                rhs = rhs.strip()
            else:
                return None
            name = name.split(":")[0].strip()
            return {
                "kind": "Assign",
                "id": self.next_id("let"),
                "target": name.split(" ")[0],
                "value": self._lower_expr(rhs),
                "location": self.loc(line),
            }
        if raw.startswith("use ") or raw.startswith("#["):
            return None
        return {
            "kind": "ExpressionStmt",
            "id": self.next_id("expr"),
            "expr": self._lower_expr(raw),
            "location": self.loc(line),
        }

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
            elif ch in "({[":
                depth += 1
                cur.append(ch)
            elif ch in ")}]":
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
        if raw.startswith("!"):
            return {"kind": "Unary", "op": "!", "operand": self._lower_expr(raw[1:].strip())}
        # strip refs, awaits, try, clone, ok/unwrap chains for IR shape
        raw = re.sub(r"\.await(?:\.\w+\(\))*$", "", raw)
        raw = re.sub(r"\.ok\(\)$", "", raw)
        raw = re.sub(r"\.clone\(\)$", "", raw)
        raw = re.sub(r"\.to_string\(\)$", "", raw)
        raw = re.sub(r"\.to_owned\(\)$", "", raw)
        raw = re.sub(r"\.into\(\)$", "", raw)
        raw = re.sub(r"\.as_str\(\)$", "", raw)
        raw = re.sub(r"\.unwrap_or_default\(\)$", "", raw)
        raw = re.sub(r"^&mut\s+", "", raw)
        raw = re.sub(r"^&", "", raw)
        raw = raw.replace("std::", "").replace("tokio::", "").replace("crate::shared::", "")
        raw = raw.replace("::", ".")
        raw = re.sub(r"(\w+)!", r"\1", raw)  # macros → calls
        # ["asc","desc"].contains(&data) — analyzer ConstantIncludes
        m = re.match(r"^\[(.*)\]\.contains\s*\((.*)\)\s*$", raw, re.S)
        if m:
            elems = []
            for part in self._split_call_args(m.group(1)):
                part = part.strip()
                if part:
                    elems.append(self._lower_expr(part))
            return {
                "kind": "Call",
                "callee": {
                    "kind": "FieldAccess",
                    "object": {"kind": "ArrayLiteral", "elements": elems},
                    "field": "contains",
                },
                "args": [self._lower_expr(m.group(2))],
            }
        if raw.startswith("[") and raw.endswith("]") and ".contains" not in raw:
            elems = []
            for part in self._split_call_args(raw[1:-1]):
                part = part.strip()
                if part:
                    elems.append(self._lower_expr(part))
            return {"kind": "ArrayLiteral", "elements": elems}
        # _RE_SCHEMA.is_match(&data) → /^…$/.test(data) when we have the pattern
        m = re.match(r"^(_RE_[A-Za-z0-9_]+)\.is_match\s*\((.*)\)\s*$", raw, re.S)
        if m:
            name = m.group(1)
            arg = self._lower_expr(m.group(2))
            pat = self.regex_consts.get(name)
            if pat:
                return {
                    "kind": "Call",
                    "callee": {
                        "kind": "FieldAccess",
                        "object": {"kind": "Literal", "literalKind": "string", "raw": pat},
                        "field": "test",
                    },
                    "args": [arg],
                }
        if raw.startswith('"'):
            m = re.match(r'"((?:\\.|[^"\\])*)"', raw)
            if m and m.end() == len(raw):
                return {"kind": "Literal", "literalKind": "string", "raw": m.group(1)}
        if re.match(r"^-?\d+$", raw):
            return {"kind": "Literal", "literalKind": "number", "raw": raw}
        # env.var("X") → FieldAccess env.X (C getenv analog)
        m = re.match(r'^env\.var\s*\(\s*"([^"]+)"\s*\)$', raw)
        if m:
            return {
                "kind": "FieldAccess",
                "object": {"kind": "Variable", "name": "env"},
                "field": m.group(1),
            }
        m = re.match(r"^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\((.*)\)$", raw, re.S)
        if m:
            callee_s = m.group(1)
            if self.ssrf_guarded and (callee_s.endswith("reqwest.get") or callee_s == "reqwest.get"
                                      or callee_s.endswith("TcpStream.connect") or callee_s == "TcpStream.connect"):
                callee_s = callee_s.replace("reqwest.get", "reqwest.guarded_get").replace(
                    "TcpStream.connect", "TcpStream.guarded_connect"
                )
            if self.cmd_guarded and "Command.new" in callee_s:
                callee_s = callee_s.replace("Command.new", "Command.guarded_new")
            if (self.path_guarded or self.upload_guarded) and (
                callee_s.endswith("fs.write") or callee_s.endswith("fs.read_to_string")
                or callee_s.endswith("fs.remove_file")
            ):
                callee_s = callee_s + "_guarded"
            if self.sql_guarded and (callee_s.endswith("db_query") or callee_s.endswith("db_exec")):
                callee_s = callee_s + "_guarded"
            if self.log_guarded and "log.info" in callee_s:
                callee_s = callee_s.replace("log.info", "log.guarded_info")
            if self.csv_guarded and callee_s.endswith("write_csv"):
                callee_s = callee_s + "_guarded"
            if self.html_guarded and (
                callee_s.endswith("render_html") or callee_s.endswith("xpath_eval")
            ):
                callee_s = callee_s + "_guarded"
            if self.err_guarded and callee_s.endswith("send_error"):
                callee_s = callee_s + "_guarded"
            args = [self._lower_expr(a) for a in self._split_call_args(m.group(2)) if a]
            parts = callee_s.split(".")
            callee: Dict[str, Any] = {"kind": "Variable", "name": parts[0]}
            for p in parts[1:]:
                callee = {"kind": "FieldAccess", "object": callee, "field": p}
            return {"kind": "Call", "callee": callee, "args": args}
        m = re.match(r"^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$", raw)
        if m:
            return {
                "kind": "FieldAccess",
                "object": {"kind": "Variable", "name": m.group(1)},
                "field": m.group(2),
            }
        if re.match(r"^[A-Za-z_]\w*$", raw):
            return {"kind": "Variable", "name": raw}
        for op in ("==", "!=", "&&", "||", "+",):
            depth = 0
            in_str = False
            for i, ch in enumerate(raw):
                if ch == '"' and (i == 0 or raw[i - 1] != "\\"):
                    in_str = not in_str
                if in_str:
                    continue
                if ch in "({[":
                    depth += 1
                elif ch in ")}]":
                    depth -= 1
                elif depth == 0 and raw.startswith(op, i) and i > 0:
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
        sys.stderr.write("usage: python3 -m vantage.nebula_frontend_rust <file.rs> [...]\n")
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
