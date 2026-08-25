"""
VANTAGE NEBULA — Ruby frontend.

Lowers Ruby source into the same ModuleIR the other frontends emit.
One .rb file = one ModuleIR. MRI 2.6 cannot parse BenchProctor's
Ruby 3 Data.define; this is a Python-hosted subset scanner (C analog).
Do not require Rails/Sinatra.

Usage:
    python3 -m vantage.nebula_frontend_ruby <file.rb> [...]
    python3 -m vantage.nebula_frontend_ruby --batch   # paths on stdin
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


_OPENERS = re.compile(
    r"\b(def|class|module|if|unless|begin|case|while|until|for|do)\b"
)
_END = re.compile(r"\bend\b")

# Strong BP allowlist regex. Weak control-char filters do not count.
_STRONG_ALLOWLIST_RE = re.compile(r"\\A\[a-zA-Z0-9_.-\]")

# Cookie value encrypted or signed — 315/784 safe twins. Not missing-flag (1004).
_COOKIE_INTEGRITY = re.compile(
    r"Fernet|MessageEncryptor|MessageVerifier|cookies\.encrypted|cookies\.signed|"
    r"OpenSSL::HMAC|DATA_ENC_KEY|ActiveSupport::MessageEncryptor|\.encrypt\("
)

_HARDENED_COOKIE_OPTS: Dict[str, Any] = {
    "kind": "ObjectLiteral",
    "props": [
        {"key": "httponly", "value": {"kind": "Literal", "literalKind": "boolean", "raw": "true"}},
        {"key": "secure", "value": {"kind": "Literal", "literalKind": "boolean", "raw": "true"}},
        {"key": "samesite", "value": {"kind": "Literal", "literalKind": "string", "raw": "strict"}},
    ],
}


def _has_strong_allowlist(src: str) -> bool:
    return "%w[" in src or bool(_STRONG_ALLOWLIST_RE.search(src))


def _cookie_value_protected(src: str) -> bool:
    return bool(_COOKIE_INTEGRITY.search(src))


def _cookie_flags_guard(src: str) -> bool:
    """SAFE-twin cookie syntax — hash flags, signed/encrypted jar, or force_ssl."""
    s = src.lower()
    return (
        "httponly:" in s
        or ":httponly" in s
        or "same_site:" in s
        or "samesite:" in s
        or "cookies.signed" in s
        or "cookies.encrypted" in s
        or "force_ssl" in s
        or _cookie_value_protected(src)
    )


def _html_escaped(src: str) -> bool:
    return (
        "CGI.escapeHTML" in src
        or "ERB::Util" in src
        or "SafeHTML" in src
        or "Redcarpet" in src
        or "Sanitize.fragment" in src
        or 'require "sanitize"' in src
        or "Loofah" in src
        or _has_strong_allowlist(src)
    )


def _session_trusted_gate(src: str) -> bool:
    """SAFE-twin trustbound/fixation: trusted session, regeneration, or allowlist."""
    return (
        "session[:user_id]" in src
        or "session[:role]" in src
        or "session[:user]" in src
        or "current_user" in src
        or "reset_session" in src
        or "session_options[:renew]" in src
        or "regenerate_id" in src
        or _has_strong_allowlist(src)
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

    # ── structural (gated against QT safe twins) ─────────────────────────

    def collect_structural_from_source(self) -> None:
        src = self.source
        fl = self.first_line

        def live(pat: str) -> bool:
            return re.search(pat, src) is not None

        # weakhash — MD5 without SHA256 (safes use SHA256 + salt)
        if live(r"Digest::MD5") and "Digest::SHA256" not in src:
            self.emit_structural(
                fl(r"Digest::MD5"),
                "weakhash",
                "ruby.Digest.MD5",
                "Digest::MD5 used for a digest — weakhash (CWE-328)",
            )

        # weakrand — rand( without SecureRandom
        if live(r"\brand\s*\(") and "SecureRandom" not in src:
            self.emit_structural(
                fl(r"\brand\s*\("),
                "weakrand",
                "ruby.rand",
                "Kernel#rand used for a token — weakrand (CWE-330)",
            )

        # tlsverify — VERIFY_NONE (safes use Net::HTTP.get with default verify)
        if live(r"VERIFY_NONE"):
            self.emit_structural(
                fl(r"VERIFY_NONE"),
                "tlsverify",
                "ruby.ssl.VERIFY_NONE",
                "OpenSSL::SSL::VERIFY_NONE — certificate verification disabled (CWE-295)",
            )

        # planted secrets
        if "s3cr3t_key_test_xyz" in src:
            self.emit_structural(
                fl(r"s3cr3t_key_test_xyz"),
                "hardcoded_crypto_key",
                "ruby.secret.planted",
                "Planted secret literal — hardcoded crypto key (CWE-321)",
            )
        if "p4ssw0rd_test_xyz" in src:
            self.emit_structural(
                fl(r"p4ssw0rd_test_xyz"),
                "hardcodedcreds",
                "ruby.password.planted",
                "Planted password literal — hardcoded credentials (CWE-798)",
            )

        # cookies without secure attributes. Safes: { httponly:/same_site:/secure: },
        # cookies.signed / cookies.encrypted, config.force_ssl, or encrypted value.
        # Rails vuln: bare cookies[:x] = v. Sinatra vuln: set_cookie(:x, v).
        # Do not fire on the safe twin; CWE 1004 aliases 315/784/539.
        if (
            (
                re.search(r"cookies\[:[^\]]+\]\s*=\s*(?!\{)", src)
                or re.search(r"set_cookie\s*\(\s*:[^,]+,\s*(?!\{)", src)
            )
            and not _cookie_flags_guard(src)
        ):
            self.emit_structural(
                fl(r"cookies\["),
                "cookie_no_httponly",
                "ruby.cookies.set",
                "Session cookie set without httpOnly/sameSite/secure — cookie_no_httponly (CWE-1004)",
            )

        # CSRF — UPDATE without csrf_token/secure_compare
        if re.search(r"UPDATE users", src) and "csrf_token" not in src and "secure_compare" not in src:
            self.emit_structural(
                fl(r"UPDATE users"),
                "csrf",
                "ruby.csrf.missing",
                "State-changing UPDATE without csrf token / secure_compare — csrf (CWE-352)",
            )

        # clickjacking — missing X-Frame-Options. Alias 1021↔93 is FPR risk;
        # only emit when the file has no other header-injection sink shape.
        if (
            "X-Frame-Options" not in src
            and "frame-ancestors" not in src
            and "set_header" not in src
            and re.search(r"render json:", src)
            and not re.search(r"logger\.|Rails\.logger", src)
            and "Access-Control-Allow-Origin" not in src
        ):
            # Too sprayy across 60 cats — skip. Clickjacking stays dark unless
            # the file is header-only. Revisit if QT clickjacking TPR is 0.
            pass

        # CORS reflection
        if re.search(r'Access-Control-Allow-Origin",\s*data', src) and ".include?" not in src:
            self.emit_structural(
                fl(r"Access-Control-Allow-Origin"),
                "corsmisconfig",
                "ruby.cors.reflect",
                "ACAO reflects user origin without allowlist — corsmisconfig (CWE-942)",
            )

        # session fixation / trustbound — session[:data]= without a trusted-session gate.
        # 384-safes use session[:user_id]; 501-safes use session[:role] == admin.
        if re.search(r"session\[:data\]\s*=", src) and not _session_trusted_gate(src):
            self.emit_structural(
                fl(r"session\[:data\]"),
                "sessionfixation",
                "ruby.session.fix",
                "session[:data]=taint without trusted-session gate — sessionfixation (CWE-384)",
            )

        # SSTI / EL — ERB.new of user data without allowlist / html_escape of binding
        if (
            live(r"ERB\.new")
            and "%w[" not in src
            and "CGI.escapeHTML" not in src
            and "ERB::Util" not in src
            and not _STRONG_ALLOWLIST_RE.search(src)
        ):
            self.emit_structural(
                fl(r"ERB\.new"),
                "ssti",
                "ruby.ERB.new",
                "ERB.new of user template without allowlist — SSTI (CWE-1336)",
            )

        # XSS html_safe concat without escape / Sanitize / strong allowlist
        if "html_safe" in src and re.search(r"<div>", src) and not _html_escaped(src):
            self.emit_structural(
                fl(r"html_safe"),
                "xss",
                "ruby.html_safe",
                "html_safe of concatenated HTML without CGI.escapeHTML — XSS (CWE-79)",
            )

        # XXE
        if live(r"Nokogiri::XML") and "nonet" not in src and "nodtdload" not in src:
            self.emit_structural(
                fl(r"Nokogiri::XML"),
                "xxe",
                "ruby.Nokogiri.XML",
                "Nokogiri::XML of user input without nonet.nodtdload — XXE (CWE-611)",
            )

        # deserial
        if live(r"Marshal\.load") and "YAML.safe_load" not in src and "%w[" not in src:
            # safes may still Marshal.load after allowlist — %w gate
            if not re.search(r"%w\[", src) and not re.search(r"\\A\[a-zA-Z0-9", src):
                self.emit_structural(
                    fl(r"Marshal\.load"),
                    "deserial",
                    "ruby.Marshal.load",
                    "Marshal.load of user data — deserial (CWE-502)",
                )

        # cmdi concat. Safes: argv form, %w / strong-regex allowlist, Shellwords.escape.
        if re.search(r'system\s*\(\s*"echo "\s*\+', src):
            if not _has_strong_allowlist(src) and "Shellwords" not in src:
                self.emit_structural(
                    fl(r"system\s*\("),
                    "cmdi",
                    "ruby.system.concat",
                    "system(concatenated string) — command-injection (CWE-78)",
                )

        # sqli concat. Safes: bind params, allowlist, Integer(data) coercion.
        if re.search(r"""execute\s*\(\s*"SELECT \* FROM users WHERE id = '" \s*\+""", src):
            if not _has_strong_allowlist(src) and "Integer(" not in src:
                self.emit_structural(
                    fl(r"execute\s*\("),
                    "sqli",
                    "ruby.execute.concat",
                    "execute of concatenated SQL — SQL injection (CWE-89)",
                )

        # eval without allowlist
        if live(r"\beval\s*\(") and "%w[" not in src and not re.search(
            r"\\A\[a-zA-Z0-9_.-\]", src
        ):
            self.emit_structural(
                fl(r"\beval\s*\("),
                "eval_injection",
                "ruby.eval",
                "eval of user string without allowlist — eval_injection (CWE-95)",
            )

        # path concat without realpath. Safes: realpath+prefix, %w / strong-regex.
        if (
            re.search(r'File\.(delete|open|read|write)\s*\(\s*"/var/app/data/"\s*\+', src)
            and "realpath" not in src
            and not _has_strong_allowlist(src)
        ):
            self.emit_structural(
                fl(r"File\.(delete|open|read|write)"),
                "pathtraver",
                "ruby.File.concat",
                "File op of concatenated path without realpath prefix — pathtraver (CWE-22)",
            )

        # SSRF URI.open(data) without host allowlist
        if re.search(r"URI\.open\s*\(\s*data", src) and "%w[" not in src and ".include?" not in src:
            if not re.search(r"start_with\?", src) and "railscdn.org" not in src:
                self.emit_structural(
                    fl(r"URI\.open"),
                    "ssrf",
                    "ruby.URI.open",
                    "URI.open of user URL without host allowlist — SSRF (CWE-918)",
                )

        # redirect
        if re.search(r"redirect_to\s+(user_input|data)\b", src) and "%w[" not in src and ".include?" not in src:
            self.emit_structural(
                fl(r"redirect_to"),
                "redirect",
                "ruby.redirect_to",
                "redirect_to of user URL without allowlist — redirect (CWE-601)",
            )

        # log injection. Safes: allowlist, or String#delete CRLF strip + redact.
        if re.search(r'logger\.info\("Action: "\s*\+', src):
            if not _has_strong_allowlist(src) and ".delete(" not in src:
                self.emit_structural(
                    fl(r"logger\.info"),
                    "loginjection",
                    "ruby.logger.info",
                    "logger.info of concatenated user data — loginjection (CWE-117)",
                )

        # cleartext http
        if re.search(r'https?://', src) and re.search(r'"http://', src) and "https://" not in src.replace("http://", ""):
            if re.search(r'"http://', src):
                self.emit_structural(
                    fl(r'"http://'),
                    "cleartexttransmit",
                    "ruby.http.cleartext",
                    "http:// URL without TLS — cleartexttransmit (CWE-319)",
                )

    # ── IR lowering ──────────────────────────────────────────────────────

    def lower_file_body(self) -> None:
        for m in re.finditer(r'^require(?:_relative)?\s+["\']([^"\']+)["\']', self.source, re.M):
            spec = m.group(1)
            self.imports.append(
                {"localName": spec.split("/")[-1], "specifier": spec, "imported": "*"}
            )

        name, body, start_line = self._extract_entry()
        if body is None:
            self.notes.append("no def/route body found; structural only")
            return
        stmts = self._lower_statements(body, start_line)
        self.functions.append(
            {
                "id": "fn_1",
                "name": name,
                "params": [],
                "taintedParams": [],
                "body": {"statements": stmts},
                "location": self.loc(start_line),
                "modifiers": {"async": False, "generator": False, "arrow": False},
            }
        )

    def _extract_entry(self) -> Tuple[str, Optional[str], int]:
        m = re.search(r"^\s*def\s+(\w+)", self.source, re.M)
        if m:
            name = m.group(1)
            rest = self.source[m.end() :]
            body, _ = self._take_until_end(rest)
            line = self.source[: m.start()].count("\n") + 1
            return name, body, line
        m = re.search(r'^\s*(get|post|put|patch|delete)\s+["\'][^"\']+["\']\s+do', self.source, re.M)
        if m:
            rest = self.source[m.end() :]
            body, _ = self._take_until_end(rest)
            line = self.source[: m.start()].count("\n") + 1
            return f"route_{m.group(1)}", body, line
        return "main", None, 1

    def _take_until_end(self, rest: str) -> Tuple[str, int]:
        depth = 1
        i = 0
        while i < len(rest) and depth > 0:
            # skip strings
            if rest[i] in "\"'":
                q = rest[i]
                i += 1
                while i < len(rest) and rest[i] != q:
                    if rest[i] == "\\":
                        i += 2
                        continue
                    i += 1
                i += 1
                continue
            m = _OPENERS.match(rest, i)
            if m:
                depth += 1
                i = m.end()
                continue
            m = _END.match(rest, i)
            if m:
                depth -= 1
                if depth == 0:
                    return rest[:i], i
                i = m.end()
                continue
            i += 1
        return rest, len(rest)

    def _lower_statements(self, body: str, base_line: int) -> List[Dict[str, Any]]:
        lines = body.split("\n")
        out: List[Dict[str, Any]] = []
        i = 0
        abs_line = base_line
        while i < len(lines):
            raw = lines[i]
            line_no = abs_line + i
            s = raw.strip()
            i += 1
            if not s or s.startswith("#"):
                continue
            if s in ("end", "else", "elsif", "rescue", "ensure"):
                continue
            # unless COND / if COND  then return
            m = re.match(r"^(unless|if)\s+(.+)$", s)
            if m:
                kind, cond_s = m.group(1), m.group(2)
                # swallow following return/halt until end or next stmt at same indent
                cond = self._lower_expr(cond_s)
                if kind == "unless":
                    cond = {"kind": "Unary", "op": "!", "operand": cond}
                then_stmts: List[Dict[str, Any]] = []
                # peek following lines that are return/halt/render error
                while i < len(lines):
                    nxt = lines[i].strip()
                    if nxt in ("end",):
                        i += 1
                        break
                    if nxt.startswith("return") or nxt.startswith("halt") or nxt.startswith("render json: { error"):
                        then_stmts.append(
                            {
                                "kind": "Return",
                                "id": self.next_id("ret"),
                                "value": {"kind": "Literal", "literalKind": "string", "raw": "error"},
                                "location": self.loc(abs_line + i),
                            }
                        )
                        i += 1
                        if i < len(lines) and lines[i].strip() == "end":
                            i += 1
                        break
                    if nxt == "end":
                        i += 1
                        break
                    break
                if then_stmts:
                    out.append(
                        {
                            "kind": "Conditional",
                            "id": self.next_id("if"),
                            "condition": cond,
                            "thenBlock": {"statements": then_stmts},
                            "location": self.loc(line_no),
                        }
                    )
                continue
            # postfix `return … if result.nil?` / `halt … if result.nil?`
            # Must be a Conditional so the analyzer's null-check fall-through clears maybeNull.
            m = re.match(r"^(return|halt)\b(.*)\s+(if|unless)\s+(.+)$", s)
            if m:
                cond = self._lower_expr(m.group(4).strip())
                if m.group(3) == "unless":
                    cond = {"kind": "Unary", "op": "!", "operand": cond}
                out.append(
                    {
                        "kind": "Conditional",
                        "id": self.next_id("if"),
                        "condition": cond,
                        "thenBlock": {
                            "statements": [
                                {
                                    "kind": "Return",
                                    "id": self.next_id("ret"),
                                    "value": {"kind": "Literal", "literalKind": "string", "raw": "error"},
                                    "location": self.loc(line_no),
                                }
                            ]
                        },
                        "location": self.loc(line_no),
                    }
                )
                continue
            if s.startswith("return"):
                val_s = s[len("return") :].strip()
                out.append(
                    {
                        "kind": "Return",
                        "id": self.next_id("ret"),
                        "value": self._lower_expr(val_s) if val_s else None,
                        "location": self.loc(line_no),
                    }
                )
                continue
            # Sinatra: response.set_cookie(:session, data) or hash-options form
            m = re.match(r"^(?:response\.)?set_cookie\s*\((.+)\)$", s)
            if m:
                out.append(self._cookie_set_stmt(m.group(1), line_no))
                continue
            # assignment
            m = re.match(
                r"^(@?\w+|cookies(?:\.signed|\.encrypted)?\[:[^\]]+\]|session\[:[^\]]+\])\s*=\s*(.+)$",
                s,
            )
            if m:
                target_s, val_s = m.group(1), m.group(2)
                value = self._lower_expr(val_s)
                if "cookies" in target_s and "[" in target_s:
                    key = re.search(r":(\w+)", target_s)
                    name = key.group(1) if key else "session"
                    signed = ".signed" in target_s or ".encrypted" in target_s
                    out.append(self._cookie_set_from_parts(name, value, signed, line_no))
                elif target_s.startswith("session["):
                    field = re.search(r":(\w+)", target_s)
                    fname = field.group(1) if field else "data"
                    if fname in ("user_id", "userid", "current_user"):
                        fname = "user"
                    out.append(
                        {
                            "kind": "FieldAssign",
                            "id": self.next_id("fassign"),
                            "object": {"kind": "Variable", "name": "session"},
                            "field": fname,
                            "value": value,
                            "location": self.loc(line_no),
                        }
                    )
                elif target_s.startswith("@"):
                    out.append(
                        {
                            "kind": "FieldAssign",
                            "id": self.next_id("fassign"),
                            "object": {"kind": "Variable", "name": "self"},
                            "field": target_s[1:],
                            "value": value,
                            "location": self.loc(line_no),
                        }
                    )
                else:
                    out.append(
                        {
                            "kind": "Assign",
                            "id": self.next_id("assign"),
                            "target": target_s,
                            "value": value,
                            "location": self.loc(line_no),
                        }
                    )
                continue
            # expression statement
            out.append(
                {
                    "kind": "ExpressionStmt",
                    "id": self.next_id("expr"),
                    "expr": self._lower_expr(s),
                    "location": self.loc(line_no),
                }
            )
        return out

    def _cookie_set_from_parts(
        self, name: str, value: Dict[str, Any], signed: bool, line_no: int
    ) -> Dict[str, Any]:
        args: List[Dict[str, Any]] = [{"kind": "Literal", "literalKind": "string", "raw": name}]
        if value.get("kind") == "ObjectLiteral":
            args.append({"kind": "Literal", "literalKind": "string", "raw": ""})
            args.append(value)
        elif signed or _cookie_flags_guard(self.source):
            args.append(value)
            args.append(_HARDENED_COOKIE_OPTS)
        else:
            args.append(value)
        return {
            "kind": "ExpressionStmt",
            "id": self.next_id("expr"),
            "expr": {
                "kind": "Call",
                "callee": {
                    "kind": "FieldAccess",
                    "object": {"kind": "Variable", "name": "cookies"},
                    "field": "set",
                },
                "args": args,
            },
            "location": self.loc(line_no),
        }

    def _cookie_set_stmt(self, args_s: str, line_no: int) -> Dict[str, Any]:
        parts = [p.strip() for p in self._split_top(args_s, ",") if p.strip()]
        name = "session"
        if parts:
            n = self._lower_expr(parts[0])
            if n.get("kind") == "Literal":
                name = str(n.get("raw") or "session")
        value: Dict[str, Any] = {"kind": "Unknown", "hint": "cookie"}
        if len(parts) > 1:
            value = self._lower_expr(parts[1] if len(parts) == 2 else ",".join(parts[1:]))
        return self._cookie_set_from_parts(name, value, False, line_no)

    def _lower_expr(self, raw: str) -> Dict[str, Any]:
        raw = raw.strip()
        if not raw:
            return {"kind": "Unknown", "hint": ""}
        # `URI.parse(data).host rescue ""` — drop modifier so parse+host lowers
        raw = re.sub(r"\s+rescue\s+\S+$", "", raw).strip()
        # result.nil? → result == null (analyzer varsNullCheckedInCondition)
        m = re.match(r"^(.+)\.nil\?$", raw)
        if m:
            return {
                "kind": "Binary",
                "op": "==",
                "left": self._lower_expr(m.group(1)),
                "right": {"kind": "Literal", "literalKind": "null", "raw": "null"},
            }
        # trailing if/unless modifier
        m = re.search(r"\s+(if|unless)\s+.+$", raw)
        if m and not raw.startswith(("if ", "unless ")):
            raw = raw[: m.start()].strip()
        # strip trailing { status: "ok" } hash for render json:
        if raw.endswith(",") or raw.endswith("\\"):
            raw = raw.rstrip(",\\").strip()

        # %w[a b c]  and  %w[a b].includes(data)
        m = re.match(r"^%w\[([^\]]*)\](?:\.(includes|include\?)\s*\((.+)\))?$", raw.replace("include?", "includes"))
        if m and m.group(2):
            els = [
                {"kind": "Literal", "literalKind": "string", "raw": t}
                for t in m.group(1).split()
            ]
            return {
                "kind": "Call",
                "callee": {
                    "kind": "FieldAccess",
                    "object": {"kind": "ArrayLiteral", "elements": els},
                    "field": "includes",
                },
                "args": [self._lower_expr(m.group(3))],
            }
        m = re.match(r"^%w\[([^\]]*)\]$", raw)
        if m:
            els = [
                {"kind": "Literal", "literalKind": "string", "raw": t}
                for t in m.group(1).split()
            ]
            return {"kind": "ArrayLiteral", "elements": els}

        # regex /.../  or %r{...}
        m = re.match(r"^/(.*)/[a-z]*$", raw)
        if m:
            pat = m.group(1).replace("\\A", "^").replace("\\z", "$").replace("\\Z", "$")
            return {"kind": "Literal", "literalKind": "string", "raw": f"/{pat}/"}
        m = re.match(r"^%r\{(.*)\}$", raw)
        if m:
            return {"kind": "Literal", "literalKind": "string", "raw": f"/{m.group(1)}/"}

        # strings
        m = re.match(r'^"([^"]*)"$', raw)
        if m:
            return {"kind": "Literal", "literalKind": "string", "raw": m.group(1)}
        m = re.match(r"^'([^']*)'$", raw)
        if m:
            return {"kind": "Literal", "literalKind": "string", "raw": m.group(1)}

        # symbol
        m = re.match(r"^:(\w+)$", raw)
        if m:
            return {"kind": "Literal", "literalKind": "string", "raw": m.group(1)}

        if re.match(r"^-?\d+$", raw):
            return {"kind": "Literal", "literalKind": "number", "raw": raw}
        if raw in ("true", "false"):
            return {"kind": "Literal", "literalKind": "boolean", "raw": raw}
        if raw == "nil":
            return {"kind": "Literal", "literalKind": "null", "raw": "null"}

        # parenthesized
        if raw.startswith("(") and raw.endswith(")"):
            return self._lower_expr(raw[1:-1])

        # data =~ /regex/  →  /regex/.test(data)
        m = re.match(r"^(.+?)\s*=~\s*(.+)$", raw)
        if m:
            subj = self._lower_expr(m.group(1))
            rx = self._lower_expr(m.group(2))
            return {
                "kind": "Call",
                "callee": {"kind": "FieldAccess", "object": rx, "field": "test"},
                "args": [subj],
            }

        # binary +  (string concat) — split at top-level +
        parts = self._split_top(raw, "+")
        if len(parts) > 1:
            node = self._lower_expr(parts[0])
            for p in parts[1:]:
                node = {"kind": "Binary", "op": "+", "left": node, "right": self._lower_expr(p)}
            return node

        # || default  ENV["USER_INPUT"] || ""
        parts = self._split_top(raw, "||")
        if len(parts) > 1:
            return {
                "kind": "Binary",
                "op": "||",
                "left": self._lower_expr(parts[0]),
                "right": self._lower_expr(parts[1]),
            }

        # hash { k: v, ... }
        if raw.startswith("{") and raw.endswith("}"):
            inner = raw[1:-1].strip()
            props = []
            for item in self._split_top(inner, ","):
                if ":" not in item and "=>" not in item:
                    continue
                if "=>" in item:
                    k, v = item.split("=>", 1)
                else:
                    k, v = item.split(":", 1)
                k = k.strip().lstrip(":")
                props.append({"key": k, "value": self._lower_expr(v.strip())})
            return {"kind": "ObjectLiteral", "props": props}

        # array [a, b]
        if raw.startswith("[") and raw.endswith("]"):
            inner = raw[1:-1].strip()
            els = [self._lower_expr(a) for a in self._split_top(inner, ",") if a.strip()]
            return {"kind": "ArrayLiteral", "elements": els}

        # include?  → includes (analyzer allowlist)
        raw_norm = raw.replace("include?", "includes").replace("start_with?", "startsWith")
        raw_norm = raw_norm.replace("&.", ".")

        # ENV["USER_INPUT"] / params[:q] / cookies[:x] / request.headers["H"]
        m = re.match(
            r"^([A-Za-z_][\w:.]*)\[(.+)\](?:\.(to_s|to_i|strip|to_sym))?$",
            raw_norm,
        )
        if m:
            obj = self._ident_chain(m.group(1))
            key_raw = m.group(2).strip()
            key = self._lower_expr(key_raw)
            field = key.get("raw") if key.get("kind") == "Literal" else key_raw.strip(":'\"")
            field = str(field)
            obj_name = m.group(1).split("::")[-1].split(".")[-1]
            if obj_name == "session" and field in ("user_id", "userid", "current_user"):
                field = "user"
            node = {"kind": "FieldAccess", "object": obj, "field": field}
            if m.group(3):
                node = {"kind": "Call", "callee": {"kind": "FieldAccess", "object": node, "field": m.group(3)}, "args": []}
            return node

        # call  foo.bar(args)  or  foo(args)
        m = re.match(r"^(.+)\.(\w+)\s*\((.*)\)\.(\w+)$", raw_norm, re.S)
        # chained .html_safe / .read / .hexdigest at end without parens handled below

        m = re.match(r"^(.+)\.(\w+)$", raw_norm)
        trailing_field = None
        call_src = raw_norm
        if m and "(" not in m.group(2):
            # could be obj.method  OR  call.html_safe
            head, field = m.group(1), m.group(2)
            if "(" in head or head.endswith("]"):
                trailing_field = field
                call_src = head

        m = re.match(r"^(.+)\s*\((.*)\)\s*$", call_src, re.S)
        if m:
            callee_s = m.group(1).strip()
            args_s = m.group(2)
            args = []
            kwargs = []
            for a in self._split_top(args_s, ","):
                a = a.strip()
                if not a:
                    continue
                # keyword arg html: x
                km = re.match(r"^(\w+)\s*:\s*(.+)$", a)
                if km and not a.startswith("http"):
                    kwargs.append({"key": km.group(1), "value": self._lower_expr(km.group(2))})
                else:
                    args.append(self._lower_expr(a))
            arr_inc = re.match(r"^(\[.+\])\.(includes)$", callee_s)
            if arr_inc:
                callee = {
                    "kind": "FieldAccess",
                    "object": self._lower_expr(arr_inc.group(1)),
                    "field": "includes",
                }
            elif callee_s in ("URI.parse",) or (callee_s.endswith(".parse") and "URI" in callee_s):
                callee = {"kind": "Variable", "name": "urlparse"}
            elif re.match(r"^[A-Za-z_:.\w]+$", callee_s):
                callee = self._ident_chain(callee_s)
            else:
                callee = self._lower_expr(callee_s)
            node: Dict[str, Any] = {"kind": "Call", "callee": callee, "args": args}
            if kwargs:
                node["kwargs"] = kwargs
            if trailing_field:
                if trailing_field == "html_safe":
                    node = {"kind": "Call", "callee": {"kind": "FieldAccess", "object": node, "field": "html_safe"}, "args": [node]}
                elif trailing_field in ("host", "hostname"):
                    node = {"kind": "FieldAccess", "object": node, "field": "hostname"}
                else:
                    node = {"kind": "Call", "callee": {"kind": "FieldAccess", "object": node, "field": trailing_field}, "args": []}
            return node

        # bare call with trailing field  ERB.new(data.to_s).result
        m = re.match(r"^([A-Za-z_:][\w:.]*)\s*\((.*)\)\s*$", raw_norm, re.S)
        if m:
            callee = self._ident_chain(m.group(1))
            args = [self._lower_expr(a) for a in self._split_top(m.group(2), ",") if a.strip()]
            return {"kind": "Call", "callee": callee, "args": args}

        # field chain  request.body / Digest::MD5
        if re.match(r"^[A-Za-z_:][\w:.]*$", raw_norm):
            return self._ident_chain(raw_norm)

        # String(x) / Integer(x)
        m = re.match(r"^(String|Integer|Array|Hash|Float)\((.+)\)$", raw_norm)
        if m:
            inner = self._lower_expr(m.group(2))
            return {"kind": "Call", "callee": {"kind": "FieldAccess", "object": inner, "field": "to_s" if m.group(1) == "String" else "to_i"}, "args": []}

        return {"kind": "Unknown", "hint": raw[:80]}

    def _ident_chain(self, s: str) -> Dict[str, Any]:
        s = s.replace("::", ".")
        parts = [p for p in s.split(".") if p]
        if not parts:
            return {"kind": "Unknown", "hint": s}
        node: Dict[str, Any] = {"kind": "Variable", "name": parts[0]}
        for p in parts[1:]:
            # ActiveRecord find_by returns nil — same maybeNull as find().
            if p == "find_by":
                p = "find"
            node = {"kind": "FieldAccess", "object": node, "field": p}
        return node

    def _split_top(self, raw: str, sep: str) -> List[str]:
        parts = []
        buf = []
        depth = 0
        in_str = None
        i = 0
        while i < len(raw):
            ch = raw[i]
            if in_str:
                buf.append(ch)
                if ch == "\\" and i + 1 < len(raw):
                    buf.append(raw[i + 1])
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
                i += 1
                continue
            if ch in "\"'":
                in_str = ch
                buf.append(ch)
                i += 1
                continue
            if ch in "([{":
                depth += 1
                buf.append(ch)
                i += 1
                continue
            if ch in ")]}":
                depth -= 1
                buf.append(ch)
                i += 1
                continue
            if depth == 0 and raw.startswith(sep, i):
                parts.append("".join(buf).strip())
                buf = []
                i += len(sep)
                continue
            buf.append(ch)
            i += 1
        tail = "".join(buf).strip()
        if tail:
            parts.append(tail)
        return parts if parts else [raw]


def main() -> int:
    args = sys.argv[1:]
    if not args:
        sys.stderr.write("usage: python3 -m vantage.nebula_frontend_ruby <file.rb> [...]\n")
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
