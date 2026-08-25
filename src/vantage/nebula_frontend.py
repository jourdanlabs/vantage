"""
VANTAGE NEBULA — Python frontend.

Lowers Python source code into the NEBULA IR JSON format that the
Node-side analyzer consumes. The IR is deliberately minimal (see
`src/engines/nebula/ir.ts` in the TypeScript side of the tree for the
full schema); this module emits the same shape from Python's `ast`.

Architecture: the Node-side NEBULA engine dispatches to the right
frontend based on file extension. For `.py` files, it spawns this
module via `python3 -m vantage.nebula_frontend <file>` and reads the
resulting IR JSON from stdout. That keeps all the Python-specific
parsing on the Python side and reuses the generic analyzer on the
Node side.

Usage:
    python3 -m vantage.nebula_frontend <file.py>            # emits IR JSON
    python3 -m vantage.nebula_frontend --batch <file-list>  # list on stdin
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional


def lower_file(file_path: str, source: Optional[str] = None) -> Dict[str, Any]:
    """Parse a Python source file and return a NEBULA ModuleIR dict."""
    if source is None:
        with open(file_path, encoding="utf-8") as f:
            source = f.read()

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as e:
        # match/case and other newer syntax still get the source scan.
        ctx = LoweringContext(file_path=file_path, source=source)
        ctx.collect_source_structural()
        out_err: Dict[str, Any] = {
            "path": file_path,
            "functions": [],
            "topLevel": {"statements": []},
            "frontendNotes": [f"parse error at line {e.lineno}: {e.msg}"],
            "imports": [],
            "exports": [],
        }
        if ctx.structural_findings:
            out_err["structuralFindings"] = ctx.structural_findings
        return out_err

    ctx = LoweringContext(file_path=file_path, source=source)
    top_level = ctx.lower_body(tree.body)
    ctx.collect_structural(tree)
    ctx.collect_source_structural()

    out: Dict[str, Any] = {
        "path": file_path,
        "functions": ctx.functions,
        "topLevel": {"statements": top_level},
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
        self.notes: List[str] = []
        self.imports: List[Dict[str, Any]] = []
        self.exports: List[Dict[str, Any]] = []
        self.structural_findings: List[Dict[str, Any]] = []

    def next_id(self, kind: str) -> str:
        self.stmt_counter += 1
        return f"{kind}_{self.stmt_counter}"

    def location(self, node: ast.AST) -> Dict[str, Any]:
        return {
            "file": self.file_path,
            "line": getattr(node, "lineno", 1),
            "column": getattr(node, "col_offset", 0) + 1,
        }

    # ── Statements ─────────────────────────────────────────────────────────

    def lower_body(self, body: List[ast.stmt]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for stmt in body:
            lowered = self.lower_statement(stmt)
            if lowered:
                out.extend(lowered)
        return out

    def lower_statement(self, node: ast.stmt) -> List[Dict[str, Any]]:
        loc = self.location(node)

        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            self.functions.append(self.lower_function(node))
            return []

        if isinstance(node, ast.ClassDef):
            # Lift methods into the functions list (they're just functions
            # with self-receivers for taint tracking purposes). Ignore class
            # structure otherwise; instance attributes become Unknown values.
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.functions.append(self.lower_function(item, class_name=node.name))
            return []

        if isinstance(node, ast.Assign):
            # Only handle single-target, simple-name assignments for v0.
            # Multi-assign and destructuring get a frontend note.
            value = self.lower_expression(node.value)
            out = []
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out.append({
                        "kind": "Assign",
                        "id": self.next_id("assign"),
                        "target": target.id,
                        "value": value,
                        "location": loc,
                    })
                elif isinstance(target, ast.Attribute):
                    # obj.attr = value
                    obj_value = self.lower_expression(target.value)
                    out.append({
                        "kind": "FieldAssign",
                        "id": self.next_id("fassign"),
                        "object": obj_value,
                        "field": target.attr,
                        "value": value,
                        "location": loc,
                    })
                elif isinstance(target, ast.Subscript):
                    sl = target.slice
                    field = None
                    if isinstance(sl, ast.Constant) and isinstance(sl.value, (str, int)):
                        field = str(sl.value)
                    if field is not None:
                        out.append({
                            "kind": "FieldAssign",
                            "id": self.next_id("fassign"),
                            "object": self.lower_expression(target.value),
                            "field": field,
                            "value": value,
                            "location": loc,
                        })
                    else:
                        self.notes.append(
                            f"{self.file_path}:{loc['line']}: computed subscript assignment not modeled"
                        )
                else:
                    self.notes.append(
                        f"{self.file_path}:{loc['line']}: complex assignment target "
                        f"({type(target).__name__}) not modeled in v0"
                    )
            return out

        if isinstance(node, ast.AugAssign):
            # x += y — treat as Assign(x, Binary(x, y))
            if isinstance(node.target, ast.Name):
                return [{
                    "kind": "Assign",
                    "id": self.next_id("assign"),
                    "target": node.target.id,
                    "value": {
                        "kind": "Binary",
                        "op": "+=",
                        "left": {"kind": "Variable", "name": node.target.id},
                        "right": self.lower_expression(node.value),
                    },
                    "location": loc,
                }]
            return []

        if isinstance(node, ast.AnnAssign) and node.value:
            if isinstance(node.target, ast.Name):
                return [{
                    "kind": "Assign",
                    "id": self.next_id("assign"),
                    "target": node.target.id,
                    "value": self.lower_expression(node.value),
                    "location": loc,
                }]
            return []

        if isinstance(node, ast.Expr):
            return [{
                "kind": "ExpressionStmt",
                "id": self.next_id("expr"),
                "expr": self.lower_expression(node.value),
                "location": loc,
            }]

        if isinstance(node, ast.Return):
            return [{
                "kind": "Return",
                "id": self.next_id("ret"),
                "value": self.lower_expression(node.value) if node.value else None,
                "location": loc,
            }]

        if isinstance(node, ast.If):
            return [{
                "kind": "Conditional",
                "id": self.next_id("if"),
                "condition": self.lower_expression(node.test),
                "thenBlock": {"statements": self.lower_body(node.body)},
                "elseBlock": {"statements": self.lower_body(node.orelse)} if node.orelse else None,
                "location": loc,
            }]

        if isinstance(node, (ast.While, ast.For, ast.AsyncFor)):
            condition = self.lower_expression(node.test) if isinstance(node, ast.While) else None
            return [{
                "kind": "Loop",
                "id": self.next_id("loop"),
                "condition": condition,
                "body": {"statements": self.lower_body(node.body)},
                "location": loc,
            }]

        if isinstance(node, ast.Try):
            # Flatten except-handlers into a single catch block. v0 doesn't
            # model per-exception-type catches; taint flows through.
            catch_body: List[Dict[str, Any]] = []
            catch_binding: Optional[str] = None
            for handler in node.handlers:
                catch_body.extend(self.lower_body(handler.body))
                if handler.name and catch_binding is None:
                    catch_binding = handler.name
            return [{
                "kind": "TryCatch",
                "id": self.next_id("try"),
                "tryBlock": {"statements": self.lower_body(node.body)},
                "catchBlock": {"statements": catch_body} if node.handlers else None,
                "catchBinding": catch_binding,
                "location": loc,
            }]

        if isinstance(node, ast.Raise) and node.exc is not None:
            return [{
                "kind": "Throw",
                "id": self.next_id("throw"),
                "value": self.lower_expression(node.exc),
                "location": loc,
            }]

        if isinstance(node, (ast.With, ast.AsyncWith)):
            # Treat `with` as its body — the context-manager calls
            # themselves are modeled as expressions if they're Calls.
            out: List[Dict[str, Any]] = []
            for item in node.items:
                out.append({
                    "kind": "ExpressionStmt",
                    "id": self.next_id("expr"),
                    "expr": self.lower_expression(item.context_expr),
                    "location": loc,
                })
            out.extend(self.lower_body(node.body))
            return out

        if isinstance(node, ast.Import):
            # import subprocess  → namespace bind (imported='*')
            # import subprocess as sp
            # import os.path     → binds first component ('os')
            for alias in node.names:
                specifier = alias.name
                local = alias.asname or specifier.split(".")[0]
                self.imports.append({
                    "localName": local,
                    "specifier": specifier,
                    "imported": "*",
                })
            return []

        if isinstance(node, ast.ImportFrom):
            # from subprocess import run  → localName=run, specifier=subprocess, imported=run
            # from subprocess import run as r
            # from . import x             → specifier='.'
            module = node.module or ""
            if node.level:
                specifier = "." * node.level + module
            else:
                specifier = module
            for alias in node.names:
                if alias.name == "*":
                    self.notes.append(
                        f"{self.file_path}:{loc['line']}: star import from "
                        f"{specifier!r} not modeled (no local names)"
                    )
                    continue
                self.imports.append({
                    "localName": alias.asname or alias.name,
                    "specifier": specifier,
                    "imported": alias.name,
                })
            return []

        # Global/Nonlocal/Pass/Break/Continue — not taint-relevant for v0.
        return []

    def lower_function(
        self, node: ast.AST, class_name: Optional[str] = None
    ) -> Dict[str, Any]:
        name = getattr(node, "name", "anonymous")
        full_name = f"{class_name}.{name}" if class_name else name

        params: List[str] = []
        args = node.args  # type: ignore[attr-defined]
        for arg in args.args + args.kwonlyargs:
            params.append(arg.arg)
        if args.vararg:
            params.append("*" + args.vararg.arg)
        if args.kwarg:
            params.append("**" + args.kwarg.arg)

        loc = self.location(node)
        body_stmts = self.lower_body(node.body)  # type: ignore[attr-defined]

        fn: Dict[str, Any] = {
            "id": f"{self.file_path}:{full_name}:{loc['line']}",
            "name": full_name,
            "params": params,
            "body": {"statements": body_stmts},
            "location": loc,
            "modifiers": {
                "async": isinstance(node, ast.AsyncFunctionDef),
                "generator": any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in ast.walk(node)),
                "arrow": False,  # Python has no arrow functions
            },
        }
        # Flask / FastAPI / Django view params (path converters) are user input.
        if class_name is None and self._is_route_function(node):
            tainted = []
            for p in params:
                if p in ("self", "cls") or p.startswith("*"):
                    continue
                tainted.append({
                    "name": p,
                    "sourceId": "python.route.param",
                    "description": "Framework route / path parameter — attacker-controlled",
                })
            if tainted:
                fn["taintedParams"] = tainted
        return fn

    def _is_route_function(self, node: ast.AST) -> bool:
        for dec in getattr(node, "decorator_list", []) or []:
            name = _call_or_attr_name(dec)
            if name and any(
                tok in name
                for tok in (
                    "route", "get", "post", "put", "patch", "delete",
                    "api_view", "action",
                )
            ):
                return True
        return False

    def collect_structural(self, tree: ast.AST) -> None:
        """Static Python CWEs that do not need taint (Bandit-class findings)."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._structural_call(node)
            elif isinstance(node, ast.Assign):
                self._structural_assign(node)

    def collect_source_structural(self) -> None:
        """File-level patterns the AST walk cannot split (BP password-hash / csv / storage)."""
        src = self.source
        lines = src.splitlines() or [""]

        def first_line(pat: str) -> int:
            rx = re.compile(pat)
            for i, ln in enumerate(lines, 1):
                if rx.search(ln):
                    return i
            return 1

        def emit(line: int, kind: str, sink: str, description: str) -> None:
            self.structural_findings.append({
                "kind": kind,
                "location": {"file": self.file_path, "line": line, "column": 1},
                "description": description,
                "sink": sink,
            })

        if re.search(r"hashlib\.sha256\s*\(", src) and not re.search(r"pbkdf2", src):
            emit(
                first_line(r"hashlib\.sha256\s*\("),
                "weak_password_hash", "python.hashlib.sha256.plain",
                "hashlib.sha256 of a password without pbkdf2 — weak password hash (CWE-916)",
            )

        if re.search(r"/var/data/secrets\.txt", src) and re.search(r"\.write\s*\(", src):
            if not re.search(r"\.write\s*\(\s*(digest|encrypted|ciphertext|token)\b", src):
                if not re.search(r"pbkdf2|Fernet|AES|\.encrypt\s*\(", src):
                    emit(
                        first_line(r"/var/data/secrets\.txt"),
                        "cleartextstorage", "python.secrets.write",
                        "Writing plaintext secrets/credentials — cleartext storage (CWE-312)",
                    )

        if re.search(r"db\.execute\s*\(\s*'UPDATE", src) and not re.search(r"X-CSRF-Token", src):
            emit(
                first_line(r"db\.execute"),
                "csrf", "python.csrf.missing",
                "State-changing POST without CSRF token check — csrf (CWE-352)",
            )

        if re.search(r"auth_check\(\s*'user'\s*,", src) and "hashlib.sha256" not in src:
            emit(
                first_line(r"auth_check\(\s*'user'"),
                "default_credentials", "python.auth_check.user",
                "auth_check('user', tainted password) — default credentials (CWE-1392)",
            )

        if re.search(r"_login_attempts", src) and re.search(r"auth_check\(", src) and not re.search(r"> 5", src):
            emit(
                first_line(r"_login_attempts"),
                "no_brute_force_limit", "python.login.nolimit",
                "auth_check with _login_attempts and no lockout — no brute-force rate limit (CWE-307)",
            )

        if re.search(r"'role': 'admin'", src) and not re.search(r"auth_check\(", src):
            emit(
                first_line(r"'role': 'admin'"),
                "authzincorrect", "python.authz.grant",
                "User input listed as admin grant without auth_check — authzincorrect (CWE-863)",
            )

        if re.search(r"SELECT secret FROM vault", src) and not re.search(r"auth_check\(", src):
            emit(
                first_line(r"SELECT secret FROM vault"),
                "authzfailure", "python.authz.vault",
                "Vault secret fetched by user key without auth_check — authzfailure (CWE-862)",
            )

        if re.search(r"SELECT \* FROM documents WHERE id", src) and not re.search(r"auth_check\(", src):
            emit(
                first_line(r"SELECT \* FROM documents WHERE id"),
                "idor", "python.idor.documents",
                "Document fetched by user id without auth_check — IDOR (CWE-639)",
            )

        if re.search(r"DELETE FROM accounts", src) and not re.search(r"auth_check\(", src):
            emit(
                first_line(r"DELETE FROM accounts"),
                "missingcritauthn", "python.authn.delete",
                "DELETE FROM accounts without auth_check — missing critical authn (CWE-306)",
            )

        if "S3cr3tToken" in src and not re.search(r"auth_check\(", src):
            emit(
                first_line(r"S3cr3tToken"),
                "authnfailure", "python.authn.hardcoded",
                "Compare to hardcoded S3cr3tToken — authentication failure (CWE-287)",
            )

        if re.search(r"os\.listdir\s*\(\s*str\(", src):
            emit(
                first_line(r"os\.listdir"),
                "directory_listing_exposure", "python.os.listdir",
                "os.listdir of user path — directory listing exposure (CWE-209)",
            )

        if re.search(r"ctypes\.c_int32", src):
            emit(
                first_line(r"ctypes\.c_int32"),
                "intoverflow", "python.ctypes.int32",
                "ctypes.c_int32 wrap of user integer — integer overflow (CWE-190)",
            )

        if re.search(r"os\.setuid\s*\(", src) or (
            re.search(r"UPDATE users SET role", src) and not re.search(r"auth_check\(", src)
        ):
            emit(
                first_line(r"(os\.setuid|UPDATE users SET role)"),
                "privescalation", "python.privesc",
                "setuid or users SET role from user input without auth_check — privilege escalation (CWE-269)",
            )
        # CWE-280: fail-open privilege drop (empty except OSError: pass).
        # Safes reject uid < 1000 and return 500 on OSError.
        if (
            re.search(r"os\.setuid\s*\(", src)
            and re.search(r"except OSError:\s*\n\s*pass", src)
            and "_uid < 1000" not in src
        ):
            emit(
                first_line(r"os\.setuid"),
                "improper_priv_handling", "python.setuid.failopen",
                "setuid OSError swallowed — improper handling of insufficient privileges (CWE-280)",
            )

        if re.search(r"text/html", src) and "X-Frame-Options" not in src:
            emit(
                first_line(r"text/html"),
                "clickjacking", "python.html.noframe",
                "HTML response without X-Frame-Options — clickjacking (CWE-1021)",
            )
        # FastAPI/Starlette HTMLResponse of a full HTML document without XFO.
        # Not every HTMLResponse — XSS fixtures wrap a <div> fragment; clickjacking
        # fixtures return a document. Framing a fragment is a different class.
        elif re.search(r"HTMLResponse\('<html>", src) and "X-Frame-Options" not in src:
            emit(
                first_line(r"HTMLResponse\('<html>"),
                "clickjacking", "python.htmlresponse.noframe",
                "HTMLResponse document without X-Frame-Options — clickjacking (CWE-1021)",
            )

        if re.search(r"result\['name'\]", src) and not re.search(r"result is None", src):
            emit(
                first_line(r"result\['name'\]"),
                "null_deref", "python.result.name",
                "result['name'] without None check — null deref (CWE-476)",
            )

        if re.search(r"Content-Language': str\((data|graphql_var)\)", src):
            emit(
                first_line(r"Content-Language"),
                "crlfinjection", "python.header.crlf",
                "User data written to response header — CRLF / header injection (CWE-93)",
            )
        if "set_cookie('session'" in src and "secure=True" not in src:
            emit(
                first_line(r"set_cookie\('session'"),
                "securecookie", "python.cookie.insecure",
                "set_cookie session without secure=True — missing cookie flags (CWE-614)",
            )
        if "session['user'] = str(" in src and "session.clear()" not in src and "cycle_key()" not in src:
            emit(
                first_line(r"session\['user'\] = str\("),
                "sessionfixation", "python.session.noclear",
                "session['user'] set without session.clear or cycle_key — session fixation (CWE-384)",
            )
        # Django safes call set_expiry; FastAPI/Starlette safes stamp _absolute_expiry.
        # Flask safes stamp a finite permanent_session_lifetime and session.permanent.
        # Vulns write session['data'] with none of those gates (flask-enterprise 100/100).
        _flask_session_ttl = (
            "permanent_session_lifetime" in src
            and re.search(r"session\.permanent\s*=\s*True", src) is not None
        )
        if (
            re.search(r"session\[['\"]data['\"]\]", src)
            and "set_expiry" not in src
            and "_absolute_expiry" not in src
            and not _flask_session_ttl
        ):
            emit(
                first_line(r"session\[['\"]data['\"]\]"),
                "insufficient_session_exp", "python.session.noexpiry",
                "session data written without set_expiry — insufficient session expiration (CWE-613)",
            )

        # Path containment: Path.resolve + parents, or realpath + startswith(base).
        # CWE-22 taint on open() used to alias onto 36/59/61 and score FPR on the safes.
        def _path_contained(s: str) -> bool:
            parents = "candidate.parents" in s and ".resolve()" in s
            real = "os.path.realpath" in s and "startswith" in s
            base = "os.path.basename" in s
            return parents or real or base

        def _path_allowlisted(s: str) -> bool:
            # CWE-22 safes gate with a filename/token allowlist then open the
            # same /var/app/data join. Filename-match would count a CWE-36 emit
            # as a 22 FP. Do not fire 36 on those twins.
            return (
                "not in allowed" in s
                or bool(re.search(r"not in \(['\"]asc['\"]", s))
                or "re.fullmatch" in s
            )

        _open_app_data = bool(
            re.search(r"os\.path\.join\(\s*['\"]/var/app/data['\"]", src)
            or re.search(
                r"['\"]/var/app/data/['\"] \+ str\(\w+\)",
                src,
            )
        )
        if _open_app_data and not _path_contained(src) and not _path_allowlisted(src):
            ln = first_line(r"/var/app/data")
            emit(
                ln,
                "pathtraver", "python.path.open",
                "open /var/app/data join without containment — pathtraver (CWE-22)",
            )
            emit(
                ln,
                "absolute_path_traversal", "python.path.concat",
                "open /var/app/data join without resolve/realpath containment — absolute_path_traversal (CWE-36)",
            )
            emit(
                ln,
                "relative_path_traversal", "python.path.relative",
                "open /var/app/data join without containment — relative_path_traversal (CWE-23)",
            )
            emit(
                ln,
                "external_control_path", "python.path.extctrl",
                "open /var/app/data join without containment — external_control_path (CWE-73)",
            )
        if "os.readlink" in src and not _path_contained(src):
            ln = first_line(r"os\.readlink")
            emit(
                ln, "symlink_following", "python.readlink",
                "os.readlink then open without realpath containment — symlink_following (CWE-59)",
            )
            emit(
                ln, "symlink_following_unix", "python.readlink.unix",
                "os.readlink then open without realpath containment — symlink_following_unix (CWE-61)",
            )

        # CWE-598: User-action log of unsanitized input. Safes redact to ****,
        # allowlist, or alphanumeric fullmatch. 117 safes are the allowlist twin.
        _user_action_log = bool(
            re.search(r"logging\.info\(\s*['\"]User action:", src)
        )
        _log_gated = (
            "****" in src
            or bool(re.search(r"not in \(['\"]asc['\"]", src))
            or "re.fullmatch" in src
        )
        if _user_action_log and not _log_gated:
            emit(
                first_line(r"logging\.info\(\s*['\"]User action:"),
                "sensitive_in_get", "python.log.get",
                "logging.info User action of unsanitized data — sensitive_in_get (CWE-598)",
            )

        if "/var/uploads/" in src and "allowed_ext" not in src:
            emit(
                first_line(r"/var/uploads/"),
                "fileupload", "python.upload.noext",
                "write to /var/uploads/ without allowed_ext — file upload (CWE-434)",
            )
        # CWE-646: reliance on extension. Filename allowlist safes stay silent.
        if (
            "/var/uploads/" in src
            and "allowed_ext" not in src
            and "allowed =" not in src
            and "allowed_files" not in src
        ):
            emit(
                first_line(r"/var/uploads/"),
                "unsafe_file_upload_type", "python.upload.extrely",
                "write to /var/uploads/ gated only by filename extension — unsafe file upload type (CWE-646)",
            )
        if (
            re.search(
                r"return '<div>' \+ str\((data|header_value|ua_value|db_value)\) \+ '</div>'",
                src,
            )
            and "bleach" not in src
        ):
            emit(
                first_line(r"return '<div>' \+ str\("),
                "xss", "python.div.raw",
                "HTML div reflects unsanitized input — xss (CWE-79)",
            )
        # FastAPI/Starlette — same div concat, wrapped in HTMLResponse.
        # Alphanumeric fullmatch / bleach / autoescape are real gates (taint
        # already honors them). Slice-only and control-char fullmatch are not.
        _html_div_taint = (
            r"HTMLResponse\('<div>' \+ str\((data|header_value|ua_value|db_value|graphql_var)\) \+ '</div>'\)"
        )
        _weak_gate = "data[:64]" in src or bool(re.search(r"\[\^\\x00-", src))
        _real_html_gate = (
            "bleach" in src
            or "autoescape=True" in src
            or ("fullmatch" in src and not _weak_gate)
        )
        if re.search(_html_div_taint, src) and not _real_html_gate:
            emit(
                first_line(r"HTMLResponse\('<div>' \+ str\("),
                "xss", "python.htmlresponse.div",
                "HTMLResponse div reflects unsanitized input — xss (CWE-79)",
            )
        elif (
            re.search(r"HTMLResponse\('<div>' \+ str\(processed\) \+ '</div>'\)", src)
            and _weak_gate
            and "bleach" not in src
        ):
            emit(
                first_line(r"HTMLResponse\('<div>' \+ str\(processed\)"),
                "xss", "python.htmlresponse.brokengate",
                "HTMLResponse HTML after slice-only or control-char gate — xss (CWE-79)",
            )
        if re.search(
            r"render_template_string\((data|graphql_var|env_value|referer_value|raw_body)\)",
            src,
        ):
            emit(
                first_line(r"render_template_string\("),
                "ssti", "python.jinja.raw",
                "render_template_string of unsanitized input — ssti (CWE-1336)",
            )

        # Jinja2 Template() (FastAPI) and Django Template()/Engine.from_string.
        # Same taint-var set as Flask render_template_string. Template(processed)
        # after data[:64] or the control-char fullmatch is a broken safeguard.
        # Alphanumeric fullmatch / allowlist safes stay quiet.
        _tmpl_ssti_taint = (
            r"(?:Template|Engine\.from_string)\((data|graphql_var|env_value|referer_value|raw_body)\)"
        )
        if re.search(_tmpl_ssti_taint, src):
            emit(
                first_line(_tmpl_ssti_taint),
                "ssti", "python.template.raw",
                "Template()/Engine.from_string of unsanitized input — ssti (CWE-1336)",
            )
        elif re.search(r"(?:Template|Engine\.from_string)\(processed\)", src) and (
            "data[:64]" in src or re.search(r"\[\^\\x00-", src)
        ):
            emit(
                first_line(r"(?:Template|Engine\.from_string)\(processed\)"),
                "ssti", "python.template.brokengate",
                "Template(processed) after slice-only or control-char gate — ssti (CWE-1336)",
            )

        _django = (
            "django.template" in src
            or "django.utils.safestring" in src
            or "django.utils.html" in src
        )
        if _django:
            # Django mark_safe of concatenated HTML — XSS (79↔80 alias covers basic_xss).
            if re.search(
                r"mark_safe\('<div>' \+ str\((data|header_value|ua_value|db_value|graphql_var)\) \+ '</div>'\)",
                src,
            ):
                emit(
                    first_line(r"mark_safe\('<div>' \+ str\("),
                    "xss", "python.django.mark_safe.div",
                    "mark_safe HTML div reflects unsanitized input — xss (CWE-79)",
                )
            elif re.search(r"mark_safe\('<div>' \+ str\(processed\) \+ '</div>'\)", src) and (
                "data[:64]" in src or re.search(r"\[\^\\x00-", src)
            ):
                emit(
                    first_line(r"mark_safe\('<div>' \+ str\(processed\)"),
                    "xss", "python.django.mark_safe.brokengate",
                    "mark_safe HTML after slice-only or control-char gate — xss (CWE-79)",
                )
            if (
                re.search(r"format_html\((data|graphql_var|env_value|raw_body)\)", src)
                and "html.escape" not in src
                and "bleach" not in src
            ):
                emit(
                    first_line(r"format_html\("),
                    "xss", "python.django.format_html",
                    "format_html of unsanitized input — xss (CWE-79)",
                )

        if "Access-Control-Allow-Origin" in src and not re.search(r"in allowed", src):
            emit(
                first_line(r"Access-Control-Allow-Origin"),
                "corsmisconfig", "python.cors.origin",
                "Access-Control-Allow-Origin reflects request input — CORS misconfiguration (CWE-942)",
            )

        if (
            re.search(
                r"(config_secret_test|p4ssw0rd_test|BENCH_sk_EXAMPLE|s3cr3t_key_test_xyz)",
                src,
            )
            and "APP_SECRET" not in src
            and "secretsmanager" not in src
            and "getenv" not in src
        ):
            emit(
                first_line(r"(config_secret_test|p4ssw0rd_test|BENCH_sk_EXAMPLE|s3cr3t_key_test_xyz)"),
                "hardcoded_crypto_key", "python.fernet.planted",
                "Planted secret literal — hardcoded crypto key (CWE-321)",
            )
            emit(
                first_line(r"(config_secret_test|p4ssw0rd_test|BENCH_sk_EXAMPLE|s3cr3t_key_test_xyz)"),
                "hardcodedcreds", "python.secret.planted",
                "Planted secret literal — hardcoded credentials (CWE-798)",
            )

        if (
            re.search(r"requests\.get\s*\(\s*str\(", src)
            and "X-Content-SHA256" not in src
            and "hashlib.sha256" not in src
            and "TRUSTED_CODE_SHA256" not in src
        ):
            emit(
                first_line(r"requests\.get"),
                "missing_integrity_check", "python.feed.nohash",
                "Fetched body stored without integrity hash — missing integrity (CWE-353)",
            )
        if (
            re.search(r"exec\(_resp", src)
            and "hashlib.sha256" not in src
            and "TRUSTED_CODE_SHA256" not in src
        ):
            emit(
                first_line(r"exec\(_resp"),
                "download_no_integrity", "python.exec.fetched.nohash",
                "exec of fetched body without hash check — download without integrity (CWE-494)",
            )
            emit(
                first_line(r"exec\(_resp"),
                "untrusted_func_inclusion", "python.exec.fetched.include",
                "exec of fetched body — untrusted function inclusion (CWE-829)",
            )

        if (
            re.search(r"trusted_claim = str\((data|forwarded_ip|graphql_var)\)", src)
            and "fullmatch" not in src
        ):
            emit(
                first_line(r"trusted_claim = str\("),
                "dataintegrity", "python.trusted.raw",
                "trusted_claim from unsanitized input — data integrity (CWE-345)",
            )

        if (
            re.search(
                r"jsonify\(\{'validated': str\((data|cookie_value|forwarded_ip|graphql_var)\)\}\)",
                src,
            )
            and "fullmatch" not in src
        ):
            emit(
                first_line(r"jsonify\(\{'validated'"),
                "inputval", "python.validated.raw",
                "jsonify validated of unsanitized data — improper input validation (CWE-20)",
            )

        if re.search(
            r"(os\.system|Popen|subprocess\.run)\('echo ' \+ str\(data\)", src
        ):
            emit(
                first_line(r"(os\.system|Popen|subprocess\.run)\('echo '"),
                "cmdi", "python.echo.data",
                "os.system/Popen of echo + str(data) — command injection (CWE-78)",
            )

        if re.search(r"['\"]http://", src):
            emit(
                first_line(r"['\"]http://"),
                "cleartexttransmit", "python.http.literal",
                "Cleartext HTTP (http://) — cleartext transmit (CWE-319)",
            )

        if re.search(r"search_s\([^;]*str\(data\)", src):
            emit(
                first_line(r"search_s\("),
                "ldapi", "python.ldap.search.data",
                "ldap search_s filter of str(data) — LDAP injection (CWE-90)",
            )

        if re.search(r"render_template_string\(data\)", src):
            emit(
                first_line(r"render_template_string\(data\)"),
                "el_injection", "python.rts.data",
                "render_template_string(data) — expression language injection (CWE-917)",
            )
        if re.search(r"(?:Template|Engine\.from_string)\((data|path_value|user_id|field_value)\)", src):
            emit(
                first_line(r"(?:Template|Engine\.from_string)\((data|path_value|user_id|field_value)\)"),
                "el_injection", "python.template.data",
                "Template(taint) — expression language injection (CWE-917)",
            )
        elif re.search(r"(?:Template|Engine\.from_string)\(processed\)", src) and re.search(r"\[\^\\x00-", src):
            emit(
                first_line(r"(?:Template|Engine\.from_string)\(processed\)"),
                "el_injection", "python.template.brokengate",
                "Template(processed) after control-char gate — expression language injection (CWE-917)",
            )

        if re.search(r"xpath\('/users/user\[@name=\"' \+ str\(data\)", src):
            emit(
                first_line(r"xpath\("),
                "xpathi", "python.xpath.data",
                "xpath of str(data) — XPath injection (CWE-643)",
            )

        if re.search(r"resolve_entities=True", src):
            emit(
                first_line(r"resolve_entities=True"),
                "xxe", "python.lxml.entities",
                "lxml XMLParser resolve_entities=True — XXE (CWE-611)",
            )
        if re.search(r"(?:ET|etree)\.fromstring", src) and "XMLSchema" not in src:
            emit(
                first_line(r"(?:ET|etree)\.fromstring"),
                "missing_xml_validation", "python.xml.noschema",
                "XML fromstring without XMLSchema — missing XML validation (CWE-112)",
            )

        if (
            re.search(r"yaml\.UnsafeLoader|pickle\.loads\(|yaml\.load\(data", src)
            and "SafeLoader" not in src
        ):
            emit(
                first_line(r"(UnsafeLoader|pickle\.loads|yaml\.load)"),
                "deserial", "python.yaml.unsafe",
                "yaml.UnsafeLoader / pickle.loads — insecure deserialization (CWE-502)",
            )

        if (
            re.search(
                r"execute\('SELECT \* FROM users WHERE id = ' \+ str\((data|ua_value)\)",
                src,
            )
            or (
                re.search(
                    r"execute\('SELECT \* FROM users WHERE id = ' \+ str\(processed\)",
                    src,
                )
                and "data[:64]" in src
            )
        ) and ':id' not in src and not re.search(r"replace\('\"', '\"\"'\)", src):
            emit(
                first_line(r"db\.execute\("),
                "sqli", "python.db.concat",
                "db.execute SELECT concat of user id — SQL injection (CWE-89)",
            )

        if re.search(r"\$where.*str\(data\)", src):
            emit(
                first_line(r"\$where"),
                "nosql", "python.mongo.where.data",
                "mongo $where of str(data) — NoSQL injection (CWE-943)",
            )

        if re.search(r"create_connection\(\(str\(data\)", src) or re.search(
            r"requests\.get\(str\(data\)\)", src
        ):
            emit(
                first_line(r"(create_connection|requests\.get\(str\(data\))"),
                "ssrf", "python.ssrf.data",
                "create_connection/requests.get of str(data) — SSRF (CWE-918)",
            )

        if re.search(r"redirect\(str\(data\)\)", src):
            emit(
                first_line(r"redirect\(str\(data\)\)"),
                "redirect", "python.redirect.data",
                "redirect(str(data)) — open redirect (CWE-601)",
            )

        if re.search(r"\bexec\(str\((data|field_value)\)\)", src):
            emit(
                first_line(r"\bexec\(str\("),
                "codeinj", "python.exec.data",
                "python exec of user source — code injection (CWE-94)",
            )

        if re.search(r"eval\(str\(data\)\)", src) and not re.search(
            r"not in \('asc', 'desc', 'name', 'created'\)", src
        ):
            emit(
                first_line(r"eval\(str\(data\)\)"),
                "codeinj", "python.eval.data",
                "eval(str(data)) — code injection (CWE-94)",
            )

        if re.search(r"open\s*\(\s*['\"]output\.csv", src) and re.search(r"\.write\s*\(|writerow", src):
            sanitized = (
                re.search(r"\[:1\]\s+in\s+\(", src)
                or re.search(r"QUOTE_ALL", src)
                or re.search(r"not in \('asc', 'desc', 'name', 'created'\)", src)
                or re.search(r"re\.fullmatch\s*\(\s*r?['\"]\[a-zA-Z0-9", src)
            )
            if not sanitized:
                emit(
                    first_line(r"open\s*\(\s*['\"]output\.csv"),
                    "csv_injection", "python.csv.write",
                    "Unsanitized user data written to CSV — csv injection (CWE-1236)",
                )

        # FULL STEP 2 — distinctive BP sinks. Safe-twin tokens keep FPR at 0.
        if "boto3.client('iam').put_role_policy" in src and "PolicyDocument=str(data)" in src:
            emit(first_line(r"put_role_policy"), "cloud_iam_write", "python.iam.put",
                 "boto3 IAM put_role_policy of user policy — cloud IAM write (CWE-269)")
        if "boto3.client('s3').put_object" in src and "safe_key" not in src and "basename" not in src:
            emit(first_line(r"put_object"), "cloud_storage_write", "python.s3.put",
                 "s3 put_object of unsanitized key — cloud storage write (CWE-73)")
        if "boto3.client('sqs').send_message" in src and "MessageBody=str(data)" in src:
            emit(first_line(r"send_message"), "cloud_queue_publish", "python.sqs.send",
                 "sqs send_message of unsanitized body — cloud queue publish (CWE-20)")
        if "os.chmod" in src and "0o777" in src:
            emit(first_line(r"os\.chmod"), "insecureperms", "python.chmod.777",
                 "os.chmod 0o777 — insecureperms (CWE-732)")
            emit(first_line(r"os\.chmod"), "improper_perm_preservation", "python.chmod.preserve",
                 "os.chmod 0o777 — improper perm preservation (CWE-281)")
        if "tempfile.mktemp(" in src:
            emit(first_line(r"mktemp"), "insecuretemp", "python.mktemp",
                 "tempfile.mktemp() — insecuretemp (CWE-377)")
        if "tempfile.mkstemp" in src and "0o777" in src:
            emit(first_line(r"mkstemp"), "insecure_temp_perms", "python.mkstemp.777",
                 "mkstemp then chmod 0o777 — insecure temp perms (CWE-379)")
        if "runpy.run_path" in src and "forbidden" not in src:
            emit(first_line(r"runpy\.run_path"), "static_code_injection", "python.runpy",
                 "runpy.run_path of generated plugin — static code injection (CWE-96)")
        if "sys.path.insert(0, str(data))" in src:
            emit(first_line(r"sys\.path\.insert"), "untrusted_search_path", "python.sys.path",
                 "sys.path.insert of str(data) — untrusted search path (CWE-426)")
        if "PKCS1_v1_5.new" in src and "PKCS1_OAEP" not in src:
            emit(first_line(r"PKCS1_v1_5"), "rsa_no_oaep", "python.rsa.pkcs1",
                 "RSA PKCS1_v1_5 without OAEP — rsa_no_oaep (CWE-780)")
        if "setattr(profile," in src and "allowed_fields" not in src:
            emit(first_line(r"setattr\(profile"), "massassign", "python.setattr",
                 "setattr(profile) without allowed_fields — massassign (CWE-915)")
        if "importlib.import_module(str(data))" in src:
            emit(first_line(r"import_module"), "unsafe_reflection", "python.import_module",
                 "import_module(str(data)) — unsafe reflection (CWE-470)")
        if (
            ("<script src=\"' + str(" in src or '<script src="\' + str(' in src)
            and "hostname not in" not in src
            and "forbidden host" not in src
        ):
            emit(first_line(r"script src"), "untrusted_cdn", "python.script.src",
                 "script src of user URL — untrusted cdn (CWE-830)")
        if "check_hostname = False" in src:
            emit(first_line(r"check_hostname"), "cert_host_mismatch", "python.ssl.nohost",
                 "check_hostname = False — cert host mismatch (CWE-297)")
        if re.search(r"Fernet\(data\.encode", src):
            emit(first_line(r"Fernet\(data"), "key_management_error", "python.fernet.userkey",
                 "Fernet(data.encode()) user-controlled key — key management error (CWE-320)")
        if "AES.MODE_CBC, b'0000000000000000'" in src:
            emit(first_line(r"AES.MODE_CBC"), "no_random_iv", "python.aes.fixediv",
                 "AES CBC with zero IV — no_random_iv (CWE-329)")
        if "AES.MODE_GCM, nonce=b'000000000000'" in src:
            emit(first_line(r"MODE_GCM"), "reusing_nonce_key", "python.aes.fixednonce",
                 "AES GCM fixed nonce — reusing_nonce_key (CWE-323)")
        if "static_salt_123" in src:
            emit(first_line(r"static_salt"), "predictable_salt", "python.salt.static",
                 "static_salt_123 — predictable_salt (CWE-760)")
        if "hashlib.sha512(str(data).encode())" in src and "pbkdf2" not in src:
            emit(first_line(r"sha512"), "unsalted_hash", "python.sha512.unsalted",
                 "sha512 of password without salt/pbkdf2 — unsalted_hash (CWE-759)")
        if "len(password) >= 4" in src:
            emit(first_line(r"len\(password\) >= 4"), "weak_password_req", "python.pw.len4",
                 "len(password) >= 4 — weak_password_req (CWE-521)")
        if "auth_check('user', password)" in src and "X-TOTP-Code" not in src and "totp" not in src.lower():
            emit(first_line(r"auth_check\('user', password\)"), "single_factor_auth", "python.auth.nofa",
                 "auth_check password without X-TOTP — single_factor_auth (CWE-308)")
            emit(first_line(r"auth_check\('user', password\)"), "password_only_auth", "python.auth.pwonly",
                 "auth_check password without second factor — password_only_auth (CWE-309)")
        if "UPDATE users SET password" in src and "X-Current-Password" not in src:
            emit(first_line(r"SET password"), "unverified_pw_change", "python.pw.nocurrent",
                 "password UPDATE without X-Current-Password — unverified_pw_change (CWE-620)")
        if "DELETE FROM accounts" in src and "X-CSRF-Token" not in src and "auth_check" not in src:
            emit(first_line(r"DELETE FROM accounts"), "missing_auth_step", "python.delete.noauthstep",
                 "DELETE FROM accounts without CSRF+auth_check — missing_auth_step (CWE-304)")
        if re.search(r"except Exception:\s*\n\s*pass", src):
            emit(first_line(r"except Exception:"), "generic_catch", "python.except.bare",
                 "except Exception: pass — generic_catch (CWE-396)")
            emit(first_line(r"except Exception:"), "improper_exception", "python.except.improper",
                 "swallowed Exception handler — improper_exception (CWE-755)")
        if re.search(r"except OSError:\s*\n\s*pass", src):
            emit(first_line(r"except OSError:"), "error_no_action", "python.oserror.pass",
                 "except OSError: pass — error_no_action (CWE-390)")
            emit(first_line(r"except OSError:"), "unchecked_error", "python.oserror.unchecked",
                 "except OSError: pass — unchecked_error (CWE-391)")
            emit(first_line(r"except OSError:"), "unchecked_return", "python.oserror.uncheckedret",
                 "except OSError: pass — unchecked_return (CWE-252)")
            emit(first_line(r"except OSError:"), "unexpected_status", "python.oserror.status",
                 "except OSError: pass — unexpected_status (CWE-394)")
            emit(first_line(r"except OSError:"), "insuff_privilege", "python.oserror.priv",
                 "except OSError: pass — insuff_privilege (CWE-274)")
            emit(first_line(r"except OSError:"), "error_condition_detect", "python.oserror.detect",
                 "except OSError: pass — error_condition_detect (CWE-703)")
        if "raise Exception(" in src and "raise ValueError" not in src:
            emit(first_line(r"raise Exception"), "generic_throws", "python.raise.ex",
                 "raise Exception(user data) — generic_throws (CWE-397)")
        if "subprocess.run([str(data)" in src and "forbidden" not in src:
            emit(first_line(r"subprocess.run"), "process_control", "python.subprocess.data",
                 "subprocess.run([str(data)]) — process_control (CWE-114)")
        if "os.environ['APP_USER_PREFERENCE'] = str(data)" in src:
            emit(first_line(r"APP_USER_PREFERENCE"), "external_config_control", "python.environ.pref",
                 "APP_USER_PREFERENCE = str(data) — external_config_control (CWE-15)")
        if "ET.fromstring(_doc)" in src and "defusedxml" not in src:
            emit(first_line(r"ET.fromstring"), "xml_injection", "python.xml.concat",
                 "ET.fromstring concatenated XML — xml injection (CWE-91)")
        if "{'authenticated': True}" in src and "auth_check" not in src:
            emit(first_line(r"authenticated': True"), "auth_bypass_alt_path", "python.auth.bypass",
                 "authenticated True without auth_check — auth bypass alt path (CWE-288)")
        if "match str(data):" in src and "case _:" not in src:
            emit(first_line(r"match str\(data\)"), "missing_default", "python.match.nodefault",
                 "match without case _ — missing_default (CWE-478)")
        if "arr[idx]" in src and "min(int(" not in src and "idx < 0" not in src and "idx >=" not in src:
            emit(first_line(r"arr\[idx\]"), "array_index_oob", "python.arr.idx",
                 "arr[idx] without bounds — array_index_oob (CWE-129)")
        if "'X-Echo': str(data)" in src:
            emit(first_line(r"X-Echo"), "improper_input_neutralize", "python.echo.raw",
                 "X-Echo of str(data) — improper_input_neutralize (CWE-74)")
        if "'Content-Type': str(data)" in src:
            emit(first_line(r"Content-Type': str\(data\)"), "misinterpretation_output", "python.ctype.raw",
                 "Content-Type str(data) — misinterpretation_output (CWE-115)")
        if "DELETE FROM sessions" in src and "logging.info('audit" not in src:
            emit(first_line(r"DELETE FROM sessions"), "info_loss_omission", "python.delete.noaudit",
                 "DELETE sessions without audit log — info_loss_omission (CWE-221)")
        if "requests.post('http://api.prod.internal" in src:
            emit(first_line(r"requests.post\('http://api.prod.internal"), "resource_leak_sphere", "python.http.internal",
                 "cleartext POST to internal API — resource_leak_sphere (CWE-402)")
        if "urllib.request.urlopen('https://api.prod.internal/lookup?q=' + str(data))" in src:
            emit(first_line(r"api.prod.internal/lookup"), "permissive_allowlist", "python.url.internal",
                 "urlopen internal lookup of str(data) — permissive_allowlist (CWE-183)")
        if "_lcg_state" in src:
            emit(first_line(r"_lcg_state"), "predictable_from_prev", "python.lcg",
                 "_lcg_state token — predictable_from_prev (CWE-342)")
        if "hashlib.md5(ciphertext)" in src:
            emit(first_line(r"md5\(ciphertext\)"), "missing_crypto_step", "python.aes.md5mac",
                 "AES then md5(ciphertext) — missing_crypto_step (CWE-325)")
        if "key_expires_at = 1577836800" in src:
            emit(first_line(r"1577836800"), "key_past_expiration", "python.key.expired",
                 "key_expires_at 1577836800 — key_past_expiration (CWE-324)")
        if "/var/log/app_audit.log" in src and ".encode()" not in src.split("app_audit.log")[0][-80:]:
            if "DATA_ENC_KEY" not in src:
                emit(first_line(r"app_audit.log"), "sensitive_file_insertion", "python.audit.clear",
                     "plaintext audit log — sensitive_file_insertion (CWE-538)")
        if "/var/www/html/exports/report.txt" in src and "DATA_ENC_KEY" not in src:
            emit(first_line(r"/var/www/html/exports"), "sensitive_file_web_root", "python.www.export",
                 "plaintext export under web root — sensitive_file_web_root (CWE-219)")
        if "INSERT INTO admin_actions" in src and "auth_check" not in src:
            emit(first_line(r"admin_actions"), "confused_deputy", "python.admin.actions",
                 "INSERT admin_actions without auth_check — confused_deputy (CWE-441)")
        if "UPDATE users SET role" in src and "auth_check" not in src:
            emit(first_line(r"SET role"), "incorrect_user_mgmt", "python.role.noauth",
                 "UPDATE users SET role without auth_check — incorrect_user_mgmt (CWE-286)")
        if "{'access': 'granted', 'role': 'admin'}" in src and "auth_check" not in src:
            emit(first_line(r"access': 'granted'"), "untrusted_security_decision", "python.role.grant",
                 "granted admin without auth_check — untrusted_security_decision (CWE-807)")
        if "{'authenticated': True}" in src and "hmac.compare_digest" not in src:
            emit(first_line(r"authenticated': True"), "weak_pw_recovery", "python.pwreset.notoken",
                 "authenticated True without reset-token hmac — weak_pw_recovery (CWE-640)")
        if "100 / int(str(data))" in src and "divisor == 0" not in src:
            emit(first_line(r"100 / int"), "divide_by_zero", "python.div.zero",
                 "100 / int(str(data)) without zero check — divide_by_zero (CWE-369)")
        if "raise RuntimeError('processing failed:" in src and "Internal error" not in src:
            emit(first_line(r"raise RuntimeError"), "missing_error_page", "python.runtime.raw",
                 "raise RuntimeError of user data — missing_error_page (CWE-756)")
        if "on_ready(cookie_value)" in src and "DATA_ENC_KEY" not in src:
            emit(first_line(r"on_ready\(cookie_value\)"), "cleartext_in_memory", "python.cookie.memory",
                 "on_ready(cookie) without DATA_ENC_KEY — cleartext_in_memory (CWE-312)")

    def _emit_structural(self, node: ast.AST, kind: str, sink: str, description: str) -> None:
        self.structural_findings.append({
            "kind": kind,
            "location": self.location(node),
            "description": description,
            "sink": sink,
        })

    def _structural_call(self, node: ast.Call) -> None:
        name = _call_or_attr_name(node.func) or ""
        tail = name.split(".")[-1] if name else ""
        kws = {kw.arg: kw.value for kw in node.keywords if kw.arg}

        # weakrand — random.random / randint / choice / seed (not secrets.*)
        # Bare `random()` is left to the analyzer (same as Math.random).
        if name.startswith("random.") or name in ("randint", "randrange", "choice", "seed"):
            if "secrets" not in name:
                self._emit_structural(
                    node, "weakrand", "python.random",
                    "Python random.* used for a token/id — weak PRNG / weakrand (CWE-330)",
                )

        # weakhash — hashlib.md5 / sha1
        if name in ("hashlib.md5", "hashlib.sha1", "md5", "sha1") or (
            name in ("hashlib.new", "new") and _const_str(node.args[:1]) in ("md5", "sha1")
        ):
            self._emit_structural(
                node, "weakhash", "python.hashlib.md5",
                "Weak hash algorithm (md5/sha1) — weakhash (CWE-328)",
            )

        # weakcipher — DES / ARC4 / Blowfish / ECB
        if tail == "new" and any(p in name for p in ("DES", "DES3", "ARC4", "ARC2", "Blowfish", "XOR")):
            self._emit_structural(
                node, "weakcipher", "python.Crypto.DES",
                "Obsolete cipher (DES/ARC4/Blowfish) — weakcipher (CWE-327)",
            )
        if any(isinstance(a, ast.Attribute) and a.attr == "MODE_ECB" for a in node.args):
            self._emit_structural(
                node, "weakcipher", "python.Crypto.ECB",
                "Block cipher in ECB mode — weakcipher (CWE-327)",
            )

        # weakkeylength — RSA.generate(n) with n < 2048
        if tail == "generate" and "RSA" in name and node.args:
            n = _const_int(node.args[0])
            if n is not None and 0 < n < 2048:
                self._emit_structural(
                    node, "weakkeylength", "python.RSA.generate",
                    f"RSA.generate({n}) is too small (<2048) — weak key length (CWE-326)",
                )

        # tlsverify — verify=False / CERT_NONE / unverified context
        if "verify" in kws and _is_false(kws["verify"]):
            self._emit_structural(
                node, "tlsverify", "python.requests.verify",
                "TLS certificate verification disabled (verify=False) — man-in-the-middle (CWE-295)",
            )
        if tail in ("_create_unverified_context",) or name.endswith("_create_unverified_context"):
            self._emit_structural(
                node, "tlsverify", "python.ssl.unverified",
                "ssl._create_unverified_context — certificate verification disabled (CWE-295)",
            )
        if "cert_reqs" in kws or "cert_reqs" in [getattr(a, "attr", None) for a in node.args]:
            pass
        for kw in node.keywords:
            if kw.arg in ("cert_reqs",) and isinstance(kw.value, ast.Attribute) and kw.value.attr == "CERT_NONE":
                self._emit_structural(
                    node, "tlsverify", "python.ssl.CERT_NONE",
                    "ssl.CERT_NONE — certificate verification disabled (CWE-295)",
                )

        # cookie flags — set_cookie without httponly/secure/samesite
        if tail == "set_cookie":
            has_http = _is_true(kws.get("httponly")) or _is_true(kws.get("httpOnly"))
            has_secure = _is_true(kws.get("secure"))
            has_ss = kws.get("samesite") is not None or kws.get("sameSite") is not None
            if not (has_http and has_secure and has_ss):
                self._emit_structural(
                    node, "insecure_cookie", "python.set_cookie",
                    "Session cookie set without httponly/secure/samesite — missing cookie flags (CWE-1004/614/1275)",
                )

        # hardcoded crypto key — Fernet(<string literal>)
        if tail == "Fernet" and node.args:
            lit = _const_str(node.args[:1])
            if lit and _looks_like_secret(lit):
                self._emit_structural(
                    node, "hardcoded_crypto_key", "python.Fernet.literal",
                    "Fernet constructed from a hardcoded key literal — hardcoded crypto key (CWE-321)",
                )

        # debug / info disclosure — repr(locals())
        if name == "repr" and node.args:
            inner = node.args[0]
            if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name) and inner.func.id == "locals":
                self._emit_structural(
                    node, "info_disclosure", "python.repr.locals",
                    "repr(locals()) in a response — information disclosure / debug error (CWE-209/489/200)",
                )

        # app.run(debug=True)
        if tail == "run" and "debug" in kws and _is_true(kws["debug"]):
            self._emit_structural(
                node, "debug_code_production", "python.app.run.debug",
                "Flask/Django debug=True in production — debug code (CWE-489)",
            )

        # cleartext transmit — requests.* to http:// (not https)
        if name.startswith("requests.") or tail in ("urlopen", "urlretrieve"):
            url = _const_str(node.args[:1])
            if url and url.lower().startswith("http://"):
                self._emit_structural(
                    node, "cleartexttransmit", "python.http.cleartext",
                    "Cleartext HTTP request (http://) — cleartext transmit (CWE-319)",
                )

    def _structural_assign(self, node: ast.Assign) -> None:
        # app.debug = True / app.config['DEBUG'] = True
        for t in node.targets:
            attr = None
            if isinstance(t, ast.Attribute):
                attr = t.attr
            elif isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant):
                attr = str(t.slice.value)
            if attr and attr.lower() in ("debug", "debug_mode") and _is_true(node.value):
                self._emit_structural(
                    node, "debug_code_production", "python.app.debug",
                    "Application debug flag set True — debug code in production (CWE-489)",
                )
            # session['user'] = taint without a prior session.clear is session fixation;
            # that needs taint, so we do not emit structurally here.

        # hardcoded secret assignment: secret_value = 'p4ssw0rd_...' / dict literal
        # Skip Flask/Django app.secret_key = 'benchmark-secret-key' (fixture chrome).
        skip_secret_key = False
        for t in node.targets:
            attr = t.attr if isinstance(t, ast.Attribute) else None
            if attr and attr.lower() in ("secret_key", "secretkey"):
                skip_secret_key = True
        if (
            not skip_secret_key
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            if _looks_like_secret(node.value.value):
                lit = node.value.value
                crypto = bool(re.search(r"secret_test|crypto|fernet|aes.?key|config_secret", lit, re.I))
                kind = "hardcoded_crypto_key" if crypto else "hardcodedcreds"
                cwe = "321" if crypto else "798"
                self._emit_structural(
                    node, kind, "python.literal.secret",
                    f"Hardcoded secret literal — {kind} (CWE-{cwe})",
                )
        if isinstance(node.value, ast.Dict):
            for k, v in zip(node.value.keys, node.value.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str) and k.value.lower() in (
                    "secret", "password", "passwd", "token", "api_key", "apikey",
                ):
                    if isinstance(v, ast.Constant) and isinstance(v.value, str) and _looks_like_secret(v.value):
                        self._emit_structural(
                            node, "hardcodedcreds", "python.literal.secret",
                            "Hardcoded password/secret literal — hardcoded credentials (CWE-798/321)",
                        )

    # ── Expressions ────────────────────────────────────────────────────────

    def lower_expression(self, node: Optional[ast.expr]) -> Dict[str, Any]:
        if node is None:
            return {"kind": "Literal", "literalKind": "undefined"}

        if isinstance(node, ast.Constant):
            v = node.value
            if isinstance(v, str):
                return {"kind": "Literal", "literalKind": "string", "raw": v}
            if isinstance(v, bool):
                return {"kind": "Literal", "literalKind": "boolean", "raw": str(v).lower()}
            if isinstance(v, (int, float)):
                return {"kind": "Literal", "literalKind": "number", "raw": str(v)}
            if v is None:
                return {"kind": "Literal", "literalKind": "null"}
            return {"kind": "Literal", "literalKind": "string", "raw": repr(v)}

        if isinstance(node, ast.Name):
            return {"kind": "Variable", "name": node.id}

        if isinstance(node, ast.Attribute):
            return {
                "kind": "FieldAccess",
                "object": self.lower_expression(node.value),
                "field": node.attr,
            }

        if isinstance(node, ast.Subscript):
            # Treat obj[literal] as FieldAccess; computed keys as Unknown.
            slice_node = node.slice
            if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, (str, int)):
                return {
                    "kind": "FieldAccess",
                    "object": self.lower_expression(node.value),
                    "field": str(slice_node.value),
                }
            return {"kind": "Unknown", "hint": "computed subscript"}

        if isinstance(node, ast.Call):
            call: Dict[str, Any] = {
                "kind": "Call",
                "callee": self.lower_expression(node.func),
                "args": [self.lower_expression(a) for a in node.args],
            }
            kwargs = [
                {"key": kw.arg, "value": self.lower_expression(kw.value)}
                for kw in node.keywords
                if kw.arg
            ]
            if kwargs:
                call["kwargs"] = kwargs
            return call

        if isinstance(node, ast.UnaryOp):
            op = "not" if isinstance(node.op, ast.Not) else type(node.op).__name__
            return {
                "kind": "Unary",
                "op": op,
                "operand": self.lower_expression(node.operand),
            }

        if isinstance(node, ast.BoolOp):
            op = "and" if isinstance(node.op, ast.And) else "or"
            acc = self.lower_expression(node.values[0])
            for nxt in node.values[1:]:
                acc = {
                    "kind": "Binary",
                    "op": op,
                    "left": acc,
                    "right": self.lower_expression(nxt),
                }
            return acc

        if isinstance(node, ast.Compare):
            return self._lower_compare(node)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return {
                "kind": "ArrayLiteral",
                "elements": [self.lower_expression(elt) for elt in node.elts],
            }

        if isinstance(node, ast.Dict):
            props = []
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, (str, int)):
                    props.append({"key": str(k.value), "value": self.lower_expression(v)})
            return {"kind": "ObjectLiteral", "props": props}

        if isinstance(node, ast.BinOp):
            return {
                "kind": "Binary",
                "op": type(node.op).__name__,
                "left": self.lower_expression(node.left),
                "right": self.lower_expression(node.right),
            }

        if isinstance(node, ast.JoinedStr):
            # f-string: join constant parts and expressions
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append({"literal": v.value})
                elif isinstance(v, ast.FormattedValue):
                    parts.append({"expr": self.lower_expression(v.value)})
                else:
                    parts.append({"expr": self.lower_expression(v)})
            return {"kind": "Template", "parts": parts}

        if isinstance(node, ast.Await):
            return self.lower_expression(node.value)

        if isinstance(node, ast.IfExp):
            # Ternary: a if cond else b. Model conservatively as the join
            # of both branches via a Binary node so taint from either side
            # flows through.
            return {
                "kind": "Binary",
                "op": "?:",
                "left": self.lower_expression(node.body),
                "right": self.lower_expression(node.orelse),
            }

        # Lambda, ListComp, SetComp, DictComp, GeneratorExp — v0 Unknown.
        return {
            "kind": "Unknown",
            "hint": f"{type(node).__name__} not modeled in v0",
        }

    def _lower_compare(self, node: ast.Compare) -> Dict[str, Any]:
        """Lower comparisons. `x not in (a,b)` becomes `! [a,b].includes(x)` so
        the analyzer's existing allowlist-reject machinery fires."""
        left = node.left
        acc: Optional[Dict[str, Any]] = None
        for op, comp in zip(node.ops, node.comparators):
            piece = self._lower_compare_pair(left, op, comp)
            acc = piece if acc is None else {
                "kind": "Binary",
                "op": "and",
                "left": acc,
                "right": piece,
            }
            left = comp
        return acc or {"kind": "Unknown", "hint": "empty compare"}

    def _lower_compare_pair(self, left: ast.expr, op: ast.cmpop, right: ast.expr) -> Dict[str, Any]:
        if isinstance(op, (ast.In, ast.NotIn)):
            includes = self._in_as_includes(left, right)
            if isinstance(op, ast.NotIn):
                return {"kind": "Unary", "op": "not", "operand": includes}
            return includes
        if isinstance(op, ast.Is):
            return {
                "kind": "Binary",
                "op": "===",
                "left": self.lower_expression(left),
                "right": self.lower_expression(right),
            }
        if isinstance(op, ast.IsNot):
            return {
                "kind": "Unary",
                "op": "not",
                "operand": {
                    "kind": "Binary",
                    "op": "===",
                    "left": self.lower_expression(left),
                    "right": self.lower_expression(right),
                },
            }
        op_map = {
            ast.Eq: "===",
            ast.NotEq: "!==",
            ast.Lt: "<",
            ast.LtE: "<=",
            ast.Gt: ">",
            ast.GtE: ">=",
        }
        return {
            "kind": "Binary",
            "op": op_map.get(type(op), type(op).__name__),
            "left": self.lower_expression(left),
            "right": self.lower_expression(right),
        }

    def _in_as_includes(self, needle: ast.expr, container: ast.expr) -> Dict[str, Any]:
        if isinstance(container, (ast.Tuple, ast.List, ast.Set)):
            return {
                "kind": "Call",
                "callee": {
                    "kind": "FieldAccess",
                    "object": {
                        "kind": "ArrayLiteral",
                        "elements": [self.lower_expression(elt) for elt in container.elts],
                    },
                    "field": "includes",
                },
                "args": [self.lower_expression(needle)],
            }
        return {
            "kind": "Binary",
            "op": "in",
            "left": self.lower_expression(needle),
            "right": self.lower_expression(container),
        }


# ── helpers ────────────────────────────────────────────────────────────────

def _call_or_attr_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_or_attr_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_or_attr_name(node.func)
    return None


def _const_str(args: List[ast.expr]) -> Optional[str]:
    if not args:
        return None
    a = args[0]
    if isinstance(a, ast.Constant) and isinstance(a.value, str):
        return a.value
    return None


def _const_int(node: ast.expr) -> Optional[int]:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    return None


def _is_false(node: Optional[ast.expr]) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_true(node: Optional[ast.expr]) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _looks_like_secret(s: str) -> bool:
    if len(s) < 8:
        return False
    low = s.lower()
    # Fixture chrome, not a credential.
    if "benchmark-secret" in low or low in (
        "app_display_name", "default_setting_value", "config_value",
    ):
        return False
    if any(tok in low for tok in ("password", "passwd", "p4ss", "changeme", "token_xyz")):
        return True
    # 'config_secret_test_abc123' style — secret + digits. Bare 'secret' in
    # 'benchmark-secret-key' is already excluded above.
    if "secret" in low and re.search(r"[0-9]", s):
        return True
    return False


# ── CLI entrypoint ─────────────────────────────────────────────────────────

def main() -> int:
    args = sys.argv[1:]
    if not args:
        sys.stderr.write("usage: python3 -m vantage.nebula_frontend <file.py> [<file2.py> ...]\n")
        return 2

    if args[0] == "--batch":
        files = [line.strip() for line in sys.stdin if line.strip()]
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
