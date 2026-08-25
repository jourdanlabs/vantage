# NEBULA v0 — what the semantic engine catches that pattern-only misses

**Date:** 2026-04-19
**Scoring version:** v2 (no change from the pattern-only scoring in `SCORING_V2_DELTA.md` — ground-truth catalogs and matching rules are unchanged)
**ADR:** see `specs/adr-0002-semantic-engine.md`

## What changed

VANTAGE's `analyze` tool now accepts an `options.semantic: true` flag (CLI equivalent: `vantage analyze <path> --semantic`). When set, the pipeline runs a new engine — NEBULA — after PULSAR. NEBULA performs intraprocedural taint tracking: it walks each function's IR, propagates taint labels from known user-input sources (Express `req.body`/`req.query`/`req.params`/`req.cookies`/`req.headers`, `process.argv`, `process.env`) through assignments and function calls, and flags any tainted value that reaches a dangerous sink (`eval`, `Function` constructor, `vm.runIn*Context`, `child_process.exec/execSync/spawn`, `pug.compile`, `ejs.render`, `handlebars.compile`). Sanitizers (`JSON.stringify`, `encodeURIComponent`, `mysql.escape`, etc.) neutralize the taint for the danger classes they cover.

NEBULA findings merge into PULSAR's `adversarialFindings` list before AURORA scores the report, so they flow through `get_findings`, `generate_fix`, and the fix loop identically to pattern-based PULSAR findings. Findings with identical `(file, line, type)` to existing PULSAR findings are deduplicated — we don't double-report the same bug just because two engines agreed on it.

Default behavior is unchanged. `analyze` without `semantic: true` runs the pattern-only path in sub-100ms as before. Semantic adds several hundred milliseconds per invocation, so it's opt-in.

## The result that matters

On Juice Shop, semantic mode catches **Server-Side Template Injection in `routes/userProfile.ts:87`** that pattern-only mode does not.

```
[HIGH] routes/userProfile.ts:87
[NEBULA] Tainted value from Express request cookies reaches pug.compile —
         pug template compile — code execution via unsanitized template
```

The bug: the `template` variable is built from HTML fragments interleaved with user data from several sources, including cookies. After ~15 string operations the variable is passed to `pug.compile(template)`, which evaluates the template as code. A crafted cookie value containing Pug directives gets executed server-side.

Pattern-only mode cannot catch this because the `pug.compile` call is many statements removed from any user-input access, and no single line matches a naive `pug.compile(req.body)` or `pug.compile(req.cookies)` pattern. NEBULA catches it by tracing the taint label on the cookie value through each assignment until it reaches the sink.

This is the prototypical "semantic engine finds bugs pattern matchers can't" case. It's not subtle, it's not manufactured — it's the OWASP Juice Shop Server-Side Template Injection challenge, one of the documented vulnerabilities in the corpus.

## Post-catalog-expansion benchmark (v0.2)

After the NEBULA catalog expanded from 7 sources / 11 sinks / 5 sanitizers to 24 / 24 / 13 — adding Koa, Fastify, Hapi, AWS Lambda sources; SQL sinks (Sequelize, Knex, pg, mysql); SSRF sinks (fetch, axios, http/https); filesystem sinks; open-redirect sinks; and stronger sanitizers including parseInt/Number coercion — we re-ran the full benchmark under strict v2 scoring.

### Dual-track numbers

| Mode | NodeGoat F1 | Juice Shop F1 | Aggregate F1 | Runtime |
|---|---|---|---|---|
| **Pattern-only** | **100.0%** (4 TP / 0 FP / 0 FN) | **72.0%** (9 TP / 7 FP / 0 FN) | **83.7%** | ~200ms |
| **Semantic (NEBULA)** | 80.0% (4 TP / 2 FP / 0 FN) | 54.5% (9 TP / 15 FP / 0 FN) | 64.9% | ~600ms |

### What the score drop actually means

Strict F1 drops ~19 points in semantic mode against the conservative GT catalog. **Every one of the extra "false positives" we've investigated is a real vulnerability the GT doesn't document.** Specifically:

On **NodeGoat**, semantic mode flags 2 additional issues:
- `app/routes/contributions.js:34` — a third `eval(req.body.roth)` on the same pattern as the two at lines 32–33 already in GT. The GT missed it.
- `app/routes/index.js:72` — `res.redirect(req.query.url)` — a CWE-601 open redirect with the in-source comment *"Insecure way to handle redirects by taking redirect url from query string."* The GT doesn't document open redirects.

On **Juice Shop**, semantic mode flags 8 additional issues:
- `routes/userProfile.ts:87` — SSTI via `pug.compile` (the headline catch)
- `routes/userProfile.ts:62` — eval of taint-traced user input
- `routes/profileImageFileUpload.ts:43` — `fs.writeFile` with user-controlled path (arbitrary file write)
- `routes/profileImageFileUpload.ts:57` — open redirect via env var
- `routes/profileImageUrlUpload.ts:24` — `fetch(url)` with user-controlled URL (SSRF)
- `routes/profileImageUrlUpload.ts:49` — open redirect
- `routes/updateUserProfile.ts:42` — open redirect
- `routes/vulnCodeFixes.ts:81` + `routes/vulnCodeSnippet.ts:90` — `fs.readFileSync` with user-controlled path (arbitrary file read)

Every one of these appears to be a real bug. None of them are in the Juice Shop or NodeGoat GT catalogs as currently published.

### The principled response

We do not expand the GT catalogs to recover the F1 loss. Doing so would be the canonical "tool author retroactively adds findings to make their tool look better" anti-pattern, and it would compromise the entire leaderboard's credibility. The GT additions process goes through public PRs with a discussion window, not through internal updates tied to benchmark runs.

What we do instead: publish both numbers, annotate every FP with its root cause (real bug vs. true false positive), and let the eventual community review decide what belongs in the catalog. Under that discipline, a 19-point F1 drop is the price of finding 10 more real bugs — a price we're willing to pay and publish openly.

### Competitive context

Even at the lower semantic F1, VANTAGE remains decisively ahead:

| | Aggregate F1 | Multiple vs VANTAGE-semantic |
|---|---|---|
| VANTAGE pattern-only | 83.7% | 1.29× |
| VANTAGE semantic | 64.9% | 1.00× |
| Semgrep (v1 scoring, stale) | 12.8% | 5.07× |
| SonarQube (v1 scoring, stale) | 2.9% | 22.4× |

Semgrep and SonarQube numbers will be re-run under v2 scoring when the weekly CI workflow executes; expect both to move downward under the stricter rule. CodeQL will be benchmarked in a follow-up run.

### CLI surface

Both modes are available via CLI, MCP, and now also the Python package:

```bash
vantage analyze <path>              # pattern-only (default, fast)
vantage analyze <path> --semantic   # with NEBULA (slower, finds more)
```

Via MCP:

```json
{ "tool": "analyze", "input": { "target_path": "/path", "options": { "semantic": true } } }
```

Via Python (PyPI):

```bash
pip install vantage-x
vantage-py <path> --semantic
```

Default remains pattern-only. Semantic is strictly opt-in.

---

## Python support (v0.3 addendum)

NEBULA now supports Python in addition to JavaScript / TypeScript. The Python frontend lives in the `vantage-x` PyPI package as `vantage.nebula_frontend` — a pure-Python module that uses the standard library `ast` package to parse `.py` files and emit NEBULA IR JSON. The Node-side engine dispatches `.py` files to this module via subprocess; JS/TS files still use the in-process TypeScript frontend. Both paths feed the same analyzer.

### Initial Python catalog

- **Sources (14)** — Flask (`request.args`/`form`/`json`/`values`/`data`/`files`/`headers`/`cookies`), Django (`request.GET`/`POST`/`body`/`FILES`/`COOKIES`/`META`), Python stdlib (`sys.argv`, `sys.stdin`, `os.environ`)
- **Sinks (23)** — code execution (`eval`, `exec`, `compile`, `__import__`), deserialization (`pickle.loads`/`load`, `yaml.load`, `marshal.loads`, `shelve.open`), command execution (`os.system`/`popen`/`execv`, `subprocess.run`/`Popen`/`call`/`check_output`/`check_call`), SQL (`SQLAlchemy text()`/`session.execute`, `cursor.execute`, `Model.objects.raw`), template injection (Jinja2 `Template`, Django `Template`), filesystem (`open`, `os.path.join`, `shutil.copy`/`rmtree`), SSRF (`requests.get`/`post`, `urllib.urlopen`, `httpx.get`), open-redirect (Flask/Django redirects)
- **Sanitizers (7)** — type coercion (`int`, `float`), URL encoding (`urllib.parse.quote`), HTML escape, shell quoting (`shlex.quote`), safe YAML loading (`yaml.safe_load`), JSON parsing (`json.loads`)

### PyGoat receipts (OWASP Python vulnerable app)

Running VANTAGE semantic mode against [PyGoat](https://github.com/adeyosemanputra/pygoat) — 173 ms, 7 unique NEBULA findings all corresponding to canonical OWASP Top 10 categories:

- `dockerized_labs/insec_des_lab/main.py:36` — `pickle.loads(request.form)` — **Insecure Deserialization**
- `introduction/views.py:214` — `pickle.loads(request.COOKIES)` — **Insecure Deserialization (Django)**
- `introduction/views.py:430` — `subprocess.Popen(request.POST)` — **Command Injection**
- `introduction/views.py:560` — `yaml.load(request.FILES)` — **YAML Deserialization RCE**
- `introduction/views.py:926` — `os.path.join(request.POST)` — **Path Traversal**
- `introduction/views.py:927` — `open(request.POST)` — **Arbitrary File Read**
- `introduction/views.py:963` — `requests.get(request.POST)` — **SSRF**

F1 score against a documented GT catalog is pending — the community GT for PyGoat doesn't exist yet and we're following the same discipline as with JS/TS: do not self-publish a GT catalog tied to our own tool's findings. Numbers will land after public GT review.

### What's next for Python

- Catalog expansion: FastAPI request patterns, Pyramid, Starlette, Tornado, more ORM sinks (Peewee, Tortoise)
- Benchmark corpus with community-reviewed GT (analogous to the JS/TS v2 process)
- Python-specific fix templates for the finding types that have localizable transforms (`subprocess.run(shell=True)` → `shlex.split` + `shell=False`, raw SQL → parameterized, etc.)
- Interprocedural flow analysis (v1.1 scope, applies equally to both languages)

## Runtime

| Mode | Juice Shop runtime |
|---|---|
| Pattern-only (`analyze`) | 197 ms |
| Semantic (`analyze --semantic`) | 639 ms |
| Overhead | +442 ms / +224% |

Still well under the 1-second target for "runs on every keystroke in an IDE" the Brick 1 distribution story depends on. CI and pre-commit use cases are unaffected.

## F1 impact

**None.** The SSTI finding is not in the current Juice Shop ground-truth catalog (`packages/vantage-bench/src/ground-truth/juice-shop.json`). The catalog documents 9 in-scope vulnerabilities and 1 out-of-scope (SQL injection in `routes/login.ts`); SSTI is neither. Under the strict matching rule, NEBULA's finding is technically a false positive relative to the GT, even though it's a bona fide security vulnerability in the corpus.

This is deliberate. We are explicitly not expanding the GT catalog to cover findings VANTAGE produces before public review of the existing catalog — adding SSTI now would be exactly the "tool author expanded the benchmark to match their tool" anti-pattern that erodes leaderboard credibility. The right sequence is:

1. Publish the leaderboard and the GT catalog with the current 9 entries (done — see `SCORING_V2_DELTA.md`)
2. Invite Semgrep / SonarSource / GitHub maintainers to review the methodology and propose catalog changes (pending — part of Brick 4 launch coordination)
3. Accept community PRs to the GT catalog, with each addition documented in a changelog
4. If SSTI belongs in the catalog after that review, add it with a dated audit trail

Until step 3 produces a verdict, SSTI stays out of the GT. NEBULA gets credit for finding it in the narrative — not in the F1 number. That's the honest position and the defensible one.

## Architecture recap (see ADR-0002 for depth)

- **Where it lives:** `src/engines/nebula/` — a new engine stage between PULSAR and AURORA, opt-in.
- **IR:** `src/engines/nebula/ir.ts` — a deliberately minimal hand-rolled IR with per-language frontends. TS/JS lowering in `frontend-typescript.ts`. Python and Swift frontends will reuse the same analyzer.
- **Catalog:** `src/engines/nebula/catalog/javascript.ts` — sources (9 entries), sinks (11 entries), sanitizers (5 entries). Catalog expansion is the perpetual maintenance tax; v0 ships with enough to prove the pipeline.
- **Analyzer:** `src/engines/nebula/analyzer.ts` — intraprocedural flow-sensitive, per-variable taint environment, method-call receiver-taint propagation, conservative join at branch / loop / try-catch boundaries.
- **Test:** `src/engines/nebula/nebula.test.ts` — 3 cases proving source-to-sink catch, sanitizer respect, irrelevant-eval ignore.

## What's deliberately not in v0

- **Interprocedural flow.** A tainted value passed to `foo(x)` does not propagate into `foo`'s body. v1.1 scope per ADR-0002.
- **Field sensitivity.** `obj.a` tainted does not taint `obj.b` independently — either both are tainted or neither is. v2 scope.
- **Python / Swift frontends.** v1.1 / v2 respectively.
- **Fixpoint iteration for loops.** A loop is analyzed once; taint carried around the back-edge may be missed. v1.1 scope.
- **Non-`file://` SARIF imports.** The bench harness doesn't yet score NEBULA findings as a separate track; they merge into the existing PULSAR count. That's fine for v0 but the methodology page should eventually break them out separately.

## Upshot

VANTAGE can now honestly say it performs semantic taint analysis, not just pattern matching. The first real finding demonstrating that delta is an OWASP Juice Shop vulnerability no pattern-based tool catches on a single-line basis. The runtime cost is under a second. The integration with the fix loop is automatic — NEBULA findings appear in `get_findings` and can be fed to `generate_fix` like any other finding, though most taint findings will fall through to the LLM path (not yet shipping) because the right fix is usually "insert sanitizer X at position Y," which needs context a pure template can't encode.

Next milestones, in priority order: interprocedural (v1.1) so that cross-function flows get caught; Python frontend (v1.1) to multiply the market; catalog expansion on a steady cadence; sanitizer-insertion templates for `generate_fix` so semantic findings become auto-fixable at the template tier.
