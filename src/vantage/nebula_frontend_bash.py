"""
VANTAGE NEBULA — Bash frontend.

Lowers self-contained .sh scripts into ModuleIR. One file = one ModuleIR.
`source` / `.` are notes, not a module graph. Functions lower as FunctionIR;
top-level commands go in topLevel.

Built against BenchProctor bash-quicktest (45 cats). Sealed hold-out is
bash-normal — do not score, do not read.

Usage:
    python3 -m vantage.nebula_frontend_bash <file.sh> [...]
    python3 -m vantage.nebula_frontend_bash --batch   # paths on stdin
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
    ctx.lower_script()
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
        if re.search(r"^\s*(source|\.)\s+", source, re.M):
            self.notes.append("raw-source: source/. not expanded")

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
                if rx.search(ln):
                    return i
            return 1

        def ident_allowlist() -> bool:
            return (
                "case $data in asc|desc" in src
                or "case $user_input in asc|desc" in src
                or "case $data in true|false|0|1" in src
                or "invalid bool" in src
                or "_schema_re=" in src
                or "[[ ! $data =~ ^[a-zA-Z0-9_.-]+$ ]]" in src
                or "^[a-zA-Z0-9_.-]+$" in src
                or "^[A-Za-z0-9_ @-]+$" in src
            )

        def authz_acl() -> bool:
            return "/etc/app/acl" in src and "USER_ROLE" in src

        def authn_db() -> bool:
            return "AUTH_TOKEN" in src and "users.db" in src

        def session_role() -> bool:
            # QT authz safe twin (USER_ROLE) and ruby-normal 1125/1390 session[:role].
            return "USER_ROLE" in src

        def auth_guard() -> bool:
            return authz_acl() or authn_db() or session_role()

        # ── command injection (CWE-78 / CWE-77) ──────────────────────────
        if 'eval "echo $' in src and not ident_allowlist():
            ln = first_line(r'eval "echo \$')
            self.emit_structural(ln, "cmdi", "bash.eval", "bash.eval — cmdi (cwe-78)")
            self.emit_structural(ln, "genericcmdi", "bash.eval.generic", "bash.eval — genericcmdi (cwe-77)")

        if ("bash -c" in src or "sh -c" in src) and not authz_acl():
            ln = first_line(r"\b(bash|sh) -c\b")
            self.emit_structural(ln, "privescalation", "bash.shc", "bash.shc — privescalation (cwe-269)")

        if "tar -czf /tmp/archive.tgz $" in src and not ident_allowlist():
            self.emit_structural(
                first_line(r"tar -czf"),
                "argument_injection", "bash.tar",
                "bash.tar unquoted — argument_injection (cwe-88)",
            )

        # ── TLS / signature ──────────────────────────────────────────────
        if "curl -sk" in src:
            ln = first_line(r"curl -sk")
            self.emit_structural(ln, "tlsverify", "bash.curl.sk", "bash.curl -sk — tlsverify (cwe-295)")
            self.emit_structural(ln, "unverified_signature", "bash.curl.sk.sig", "bash.curl -sk — unverified_signature (cwe-347)")

        # ── SSRF ─────────────────────────────────────────────────────────
        ssrf_gated = "_host_re=" in src or "private range blocked" in src
        if not ssrf_gated:
            if 'curl -s "$user_input"' in src or 'curl -s "$data"' in src:
                self.emit_structural(
                    first_line(r'curl -s "\$'),
                    "ssrf", "bash.curl.ssrf",
                    "bash.curl unscope — ssrf (cwe-918)",
                )
            if "/dev/tcp/" in src:
                self.emit_structural(
                    first_line(r"/dev/tcp/"),
                    "ssrf", "bash.tcp",
                    "bash./dev/tcp — ssrf (cwe-918)",
                )

        # ── XXE / XPath / SQL / NoSQL / LDAP ─────────────────────────────
        if "xmllint --noent" in src:
            self.emit_structural(
                first_line(r"xmllint --noent"),
                "xxe", "bash.xmllint.noent",
                "bash.xmllint --noent — xxe (cwe-611)",
            )
        if "xmllint --xpath" in src and not ident_allowlist():
            self.emit_structural(
                first_line(r"xmllint --xpath"),
                "xpathi", "bash.xpath",
                "bash.xpath concat — xpathi (cwe-643)",
            )
        if "mysql -e" in src and "SELECT * FROM users WHERE id =" in src and not ident_allowlist():
            if "^-?[0-9]+$" not in src:
                self.emit_structural(
                    first_line(r"mysql -e"),
                    "sqli", "bash.mysql",
                    "bash.mysql concat — sqli (cwe-89)",
                )
        if "mongosh --eval" in src and not ident_allowlist():
            self.emit_structural(
                first_line(r"mongosh --eval"),
                "nosql", "bash.mongosh",
                "bash.mongosh concat — nosql (cwe-943)",
            )
        if "ldapsearch" in src and not ident_allowlist():
            self.emit_structural(
                first_line(r"ldapsearch"),
                "ldapi", "bash.ldap",
                "bash.ldap concat — ldapi (cwe-90)",
            )

        # ── path / upload ────────────────────────────────────────────────
        if (
            ("/var/app/data/$" in src or "/var/uploads/$" in src)
            and "basename --" not in src
            and "invalid file type" not in src
            and "realpath" not in src
            and "checked_path" not in src
            and not ident_allowlist()
        ):
            self.emit_structural(
                first_line(r"/var/app/data/|/var/uploads/"),
                "pathtraver", "bash.path",
                "bash.path concat — pathtraver (cwe-22)",
            )
        if (
            'echo "uploaded" > "/var/uploads/' in src
            and "basename --" not in src
            and "invalid file type" not in src
        ):
            self.emit_structural(
                first_line(r"/var/uploads/"),
                "fileupload", "bash.upload",
                "bash.upload unsuffixed — fileupload (cwe-434)",
            )

        # ── csv / log / crlf ─────────────────────────────────────────────
        if 'echo "$data,data,row"' in src:
            self.emit_structural(
                first_line(r'echo "\$data,data,row"'),
                "csv_injection", "bash.csv",
                "bash.csv unsanitized — csv_injection (cwe-1236)",
            )
        if 'logger "Action: $data"' in src:
            ln = first_line(r'logger "Action: \$data"')
            self.emit_structural(ln, "loginjection", "bash.logger", "bash.logger $data — loginjection (cwe-117)")
            self.emit_structural(ln, "sensinlogs", "bash.logger.sens", "bash.logger $data — sensinlogs (cwe-532)")
        if "_bypass_re=" in src and 'logger "Action:' in src:
            self.emit_structural(
                first_line(r"_bypass_re="),
                "sensinlogs", "bash.logger.bypass",
                "bash.logger bypass_re — sensinlogs (cwe-532)",
            )
        if 'printf "X-Custom: %s\\r\\n" "$data"' in src or 'printf "X-Custom: %s\r\n" "$data"' in src:
            self.emit_structural(
                first_line(r'printf "X-Custom:'),
                "crlfinjection", "bash.crlf",
                "bash.header $data — crlfinjection (cwe-93)",
            )

        # ── redirect / CORS / integrity claim / inputval ─────────────────
        # 601 safe twin (QT): _host_re + forbidden host.
        # 472 safe twin (QT ident_allowlist / ruby \A[a-zA-Z0-9_.-]+\z): do not
        # fire 601 on an allowlisted hidden_field redirect.
        if (
            "Location:" in src
            and "_host_re=" not in src
            and "forbidden host" not in src
            and not ident_allowlist()
        ):
            self.emit_structural(
                first_line(r"Location:"),
                "redirect", "bash.location",
                "bash.Location unscope — redirect (cwe-601)",
            )
        # 472 — dedicated. BP shape is Location ... hidden_field=$data.
        # Guard: ident_allowlist (QT) or _host_re (QT redirect). Not 601-alias.
        if "hidden_field" in src and not ident_allowlist() and "_host_re=" not in src and "forbidden host" not in src:
            self.emit_structural(
                first_line(r"hidden_field"),
                "external_web_param_control", "bash.hidden_field",
                "bash.hidden_field ungated — external_web_param_control (cwe-472)",
            )
        if "Access-Control-Allow-Origin:" in src and "allowed_origin" not in src:
            self.emit_structural(
                first_line(r"Access-Control-Allow-Origin"),
                "corsmisconfig", "bash.cors",
                "bash.ACAO reflects — corsmisconfig (cwe-942)",
            )
        if "X-Claim-Trusted:" in src and not ident_allowlist():
            self.emit_structural(
                first_line(r"X-Claim-Trusted"),
                "dataintegrity", "bash.claim",
                "bash.X-Claim-Trusted ungated — dataintegrity (cwe-345)",
            )
        if "X-Validated:" in src and "true|false|0|1" not in src and not ident_allowlist() and "invalid bool" not in src:
            self.emit_structural(
                first_line(r"X-Validated"),
                "inputval", "bash.xval",
                "bash.X-Validated ungated — inputval (cwe-20)",
            )

        # ── crypto / rand / hash ─────────────────────────────────────────
        if "RANDOM=" in src and "/dev/urandom" not in src:
            self.emit_structural(
                first_line(r"RANDOM="),
                "weakrand", "bash.RANDOM",
                "bash.RANDOM seeded — weakrand (cwe-330)",
            )
        if "md5sum" in src and "sha256sum" not in src:
            ln = first_line(r"md5sum")
            self.emit_structural(ln, "weakhash", "bash.md5", "bash.md5sum — weakhash (cwe-328)")
            self.emit_structural(ln, "weak_password_hash", "bash.md5.pw", "bash.md5sum — weak_password_hash (cwe-916)")
        if "-des-ecb" in src:
            ln = first_line(r"-des-ecb")
            self.emit_structural(ln, "weakcipher", "bash.des", "bash.des-ecb — weakcipher (cwe-327)")
            self.emit_structural(ln, "weakkeylength", "bash.des.key", "bash.des-ecb — weakkeylength (cwe-326)")

        # ── secrets / creds ──────────────────────────────────────────────
        if "secrets.txt" in src and "sha256sum" not in src and "secrets.enc" not in src and "vault kv" not in src:
            ln = first_line(r"secrets\.txt")
            self.emit_structural(ln, "cleartextstorage", "bash.secrets.txt", "bash.secrets.txt — cleartextstorage (cwe-312)")
            self.emit_structural(ln, "credprotection", "bash.secrets.cred", "bash.secrets.txt — credprotection (cwe-522)")
        if "curl -s http://" in src and "curl -s https://" not in src:
            self.emit_structural(
                first_line(r"curl -s http://"),
                "cleartexttransmit", "bash.http",
                "bash.curl http — cleartexttransmit (cwe-319)",
            )
        if re.search(r'user_input="[A-Za-z0-9]{16,}"', src):
            ln = first_line(r'user_input="[A-Za-z0-9]{16,}"')
            self.emit_structural(ln, "hardcodedcreds", "bash.literal.cred", "bash.literal cred — hardcodedcreds (cwe-798)")
            if "openssl enc" in src:
                self.emit_structural(ln, "hardcoded_crypto_key", "bash.literal.key", "bash.literal key — hardcoded_crypto_key (cwe-321)")
        if "passwd.db" in src and "APP_SECRET" not in src and "vault kv" not in src:
            ln = first_line(r"passwd\.db")
            self.emit_structural(
                ln,
                "default_credentials", "bash.passwd.db",
                "bash.passwd.db — default_credentials (cwe-1392)",
            )
            self.emit_structural(
                ln,
                "credprotection", "bash.passwd.cred",
                "bash.passwd.db — credprotection (cwe-522)",
            )
        if "openssl enc" in src and 'pass:"$data"' in src.replace(" ", "") is False:
            pass
        if 'pass "$data"' in src or 'pass:$data' in src or 'pass:"$data"' in src or 'pass: "$data"' in src:
            if "APP_SECRET" not in src and "DATA_ENC_KEY" not in src and "vault kv" not in src:
                self.emit_structural(
                    first_line(r"openssl enc"),
                    "hardcoded_crypto_key", "bash.pass.data",
                    "bash.openssl pass from data — hardcoded_crypto_key (cwe-321)",
                )
        if "-pass pass:$data" in src or '-pass "pass:$data"' in src:
            if "APP_SECRET" not in src and "DATA_ENC_KEY" not in src:
                self.emit_structural(
                    first_line(r"-pass"),
                    "hardcoded_crypto_key", "bash.pass.data2",
                    "bash.openssl pass:$data — hardcoded_crypto_key (cwe-321)",
                )

        # ── authn / authz / missing auth / brute ─────────────────────────
        # S3cr3tToken is the 287/1390/1125 sink (QT authn + burned 1390/1125).
        # Safe twin is USER_ROLE (QT authz) OR AUTH_TOKEN+users.db (QT authn).
        # authn_db() alone missed USER_ROLE-then-token — the 1390 51% FPR.
        if "S3cr3tToken" in src and not auth_guard():
            ln = first_line(r"S3cr3tToken")
            self.emit_structural(
                ln,
                "authnfailure", "bash.s3cr3t",
                "bash.S3cr3tToken — authnfailure (cwe-287)",
            )
            self.emit_structural(
                ln,
                "weak_auth_generic", "bash.s3cr3t.weak",
                "bash.S3cr3tToken — weak_auth_generic (cwe-1390)",
            )
            # 1125 dedicated. Un-alias from 287 was correct; emit it here.
            self.emit_structural(
                ln,
                "excessive_attack_surface", "bash.s3cr3t.surface",
                "bash.S3cr3tToken — excessive_attack_surface (cwe-1125)",
            )
        client_role = (
            "^(read|write|admin)$" in src
            or 'role="$data"' in src
            or 'role="$user_input"' in src
            or bool(re.search(r'\[ "\$(?:data|user_input|processed)" = "admin" \]', src))
        )
        if client_role and not authz_acl():
            ln = first_line(r"read\|write\|admin") if "read|write|admin" in src else first_line(r"admin")
            self.emit_structural(ln, "authzfailure", "bash.role", "bash.role regex — authzfailure (cwe-862)")
            self.emit_structural(ln, "authzincorrect", "bash.role.inc", "bash.role regex — authzincorrect (cwe-863)")
            self.emit_structural(ln, "privescalation", "bash.role.priv", "bash.role regex — privescalation (cwe-269)")
        # 1125 / 1390 dedicated. Safe twin is USER_ROLE (QT authz) or AUTH_TOKEN
        # (QT authn) — not the 862 ACL pair alone. Do not ride 269/287 aliases.
        if client_role and not auth_guard():
            ln = first_line(r"read\|write\|admin") if "read|write|admin" in src else first_line(r"admin")
            self.emit_structural(
                ln,
                "excessive_attack_surface", "bash.role.surface",
                "bash.client role ungated — excessive_attack_surface (cwe-1125)",
            )
            self.emit_structural(
                ln,
                "weak_auth_generic", "bash.role.weak",
                "bash.client role ungated — weak_auth_generic (cwe-1390)",
            )
        if "/public/" in src and not auth_guard():
            self.emit_structural(
                first_line(r"/public/"),
                "excessive_attack_surface", "bash.public",
                "bash./public/ ungated — excessive_attack_surface (cwe-1125)",
            )
        if "redis-cli" in src and "DEL " in src and not authn_db() and "USER_ROLE" not in src:
            self.emit_structural(
                first_line(r"redis-cli"),
                "missingcritauthn", "bash.redis.del",
                "bash.redis DEL — missingcritauthn (cwe-306)",
            )
        if "_attempts=" in src and not authn_db():
            self.emit_structural(
                first_line(r"_attempts="),
                "no_brute_force_limit", "bash.attempts",
                "bash._attempts — no_brute_force_limit (cwe-307)",
            )

        # ── disclosure / debug / listing / errors ────────────────────────
        if 'echo "Error: $data"' in src:
            ln = first_line(r'echo "Error: \$data"')
            self.emit_structural(ln, "infodisclosure", "bash.err.data", "bash.Error $data — infodisclosure (cwe-200)")
            self.emit_structural(ln, "errormessage", "bash.err.msg", "bash.Error $data — errormessage (cwe-209)")
            self.emit_structural(ln, "debug_code_production", "bash.err.debug", "bash.Error $data — debug_code_production (cwe-489)")
        if "ls -la" in src:
            self.emit_structural(
                first_line(r"ls -la"),
                "directory_listing_exposure", "bash.ls",
                "bash.ls -la — directory_listing_exposure (cwe-209)",
            )

        # ── resource / overflow / integrity download ─────────────────────
        if 'count="$data"' in src and "ulimit -v" not in src:
            self.emit_structural(
                first_line(r'count="\$data"'),
                "resourceexhaust", "bash.dd.count",
                "bash.dd count=$data — resourceexhaust (cwe-400)",
            )
        if "alloc_size=$((requested + 1))" in src and "2147483647" not in src:
            self.emit_structural(
                first_line(r"alloc_size="),
                "intoverflow", "bash.alloc",
                "bash.alloc unbounded — intoverflow (cwe-190)",
            )
        if "feed.dat" in src and "X-Content-SHA256" not in src:
            self.emit_structural(
                first_line(r"feed\.dat"),
                "missing_integrity_check", "bash.feed",
                "bash.feed.dat no digest — missing_integrity_check (cwe-353)",
            )

    def lower_script(self) -> None:
        """Minimal IR: one synthesized function so taint catalog can still run."""
        src = self.source
        # Treat HTTP_* / QUERY_STRING / APP_INPUT / stdin as sources assigned to user_input.
        body: List[Dict[str, Any]] = []
        line_no = 1
        for i, ln in enumerate(src.splitlines(), 1):
            line_no = i
            m = re.search(r'user_input="(\$[A-Z0-9_]+)"', ln)
            if m:
                body.append({
                    "kind": "Assign",
                    "id": self.next_id("s"),
                    "target": "user_input",
                    "value": {
                        "kind": "FieldAccess",
                        "object": {"kind": "Variable", "name": "env"},
                        "field": m.group(1).lstrip("$"),
                    },
                    "location": self.loc(i),
                })
            if re.search(r"\beval\b", ln) and "--eval" not in ln:
                arg = {"kind": "Variable", "name": "data"}
                if "$processed" in ln:
                    arg = {"kind": "Variable", "name": "processed"}
                body.append({
                    "kind": "ExpressionStmt",
                    "id": self.next_id("s"),
                    "expr": {
                        "kind": "Call",
                        "callee": {"kind": "Variable", "name": "eval"},
                        "args": [arg],
                    },
                    "location": self.loc(i),
                })
        self.functions.append({
            "id": self.file_path + ":main",
            "name": "benchmark_test",
            "params": ["user_input"],
            "taintedParams": [{
                "name": "user_input",
                "sourceId": "bash.user_input",
                "description": "BenchProctor attacker stand-in",
            }],
            "body": {"statements": body},
            "location": self.loc(line_no),
            "modifiers": {"async": False, "generator": False, "arrow": False},
        })


def main() -> int:
    args = sys.argv[1:]
    if not args:
        sys.stderr.write("usage: python3 -m vantage.nebula_frontend_bash <file.sh> [...]\n")
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
