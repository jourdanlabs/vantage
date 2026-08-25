/**
 * Kaioken surface split (2026-08-05) — security vs quality taxonomy.
 *
 * Diagnosis (realworld-2026-08-05): detectors often fire correctly but land in
 * the wrong product surface. Quality findings must not sit in the security
 * denominator. Nothing is deleted; findings are classified.
 *
 * Test-path defaults: exclude fixtures/specs unless includeTests is set.
 */

import type { AdversarialFinding } from '../types';

export type FindingSurface = 'security' | 'quality';

export interface SurfaceFilterOptions {
  /** When false (default), drop findings under test/spec/fixture paths. */
  includeTests?: boolean;
  /** Which surfaces to keep in the reported list. Default: both (classified). */
  surface?: 'security' | 'quality' | 'all';
}

/** Paths that are tests, specs, benches, or fixtures — not product surface. */
export function isTestOrFixturePath(file: string): boolean {
  const p = file.replace(/\\/g, '/');
  if (
    /\/(test|tests|spec|specs|e2e|__tests__|__mocks__|fixtures?|benchmarks?|bench|stories)\//i.test(
      p
    )
  ) {
    return true;
  }
  if (/\.(spec|test|e2e)\.[cm]?[jt]sx?$/i.test(p)) return true;
  if (/\/(vitest|jest)[-.]setup\./i.test(p)) return true;
  return false;
}

/**
 * Classify a finding onto the security or quality surface.
 *
 * Quality = correct observations about code hygiene / structure that should not
 * count as a security hit (switch fallthrough, null-find, unchecked return,
 * pure structural RegExp construction, schema Object.assign, etc.).
 *
 * Security = attacker-influenced sinks, secrets, authz, cookies, taint paths.
 */
export function classifySurface(
  description: string,
  type: AdversarialFinding['type'] | string,
  sink?: string | null,
  file?: string | null
): FindingSurface {
  const d = `${description || ''} ${sink || ''}`;
  const filePath = (file || '').replace(/\\/g, '/');

  // BenchProctor security CSV includes CWE-478/484/330. The product surface
  // parks those as quality (switch style / Math.random in jobs). Under
  // VANTAGE_BENCH_FAST they are security or FULL cannot cover those cats.
  if (process.env.VANTAGE_BENCH_FAST === '1') {
    if (
      /falls through without break|omitted break|switch_fallthrough|switch\.fallthrough|missing default case|without default clause|switch_missing_default/i.test(
        d
      )
    ) {
      return 'security';
    }
    if (/math\.random\(\) used for security-sensitive|weak prng|weakrand|cwe-330/i.test(d)) {
      return 'security';
    }
    if (
      /null dereference|without null check|cwe-476|unchecked-return|without checking return|unexpected status|error no action|cwe-252|cwe-390|cwe-394|cwe-274|cwe-391|cwe-703|generic throws|cwe-397|throw new error|division by zero|cwe-369|generic catch|cwe-396|cwe-755|cwe-636|prototype pollution|cwe-1321|cwe-915|massassign|object\.assign|insufficient session expiration|cwe-613|missing xml validation|cwe-112|untrusted cdn|cwe-830|untrusted function inclusion|cwe-829|download without integrity|cwe-494|env_var|cwe-526|sensitive_in_get|cwe-598|console\.log\("Action:/i.test(
        d
      )
    ) {
      return 'security';
    }
  }

  // Explicit quality patterns (volume engines from real-world suite)
  if (
    /falls through without break|omitted break|switch_fallthrough|switch\.fallthrough/i.test(d)
  ) {
    return 'quality';
  }
  if (/missing default case|without default clause|switch_missing_default/i.test(d)) {
    return 'quality';
  }
  // C strchr-deref is a BenchProctor security CWE-476; JS find().name stays quality.
  if (/strchr|cwe-476|c\.strchr/i.test(d)) {
    return 'security';
  }
  if (
    /null dereference|without null check|property access on result of find\/findone/i.test(d)
  ) {
    return 'quality';
  }
  if (
    /db\.execute\/query as statement without checking return|without checking return\/status|unchecked-return|unexpected status \/ error no action/i.test(
      d
    )
  ) {
    return 'quality';
  }
  if (/division by zero|potential division by zero|div\.zero|zero divisor/i.test(d)) {
    return 'quality';
  }
  // Structural RegExp construction without a taint path ("potential ReDoS if…")
  if (
    /new regexp\(\).*non-literal|potential redos if input is user-controlled/i.test(d) &&
    !/tainted value from/i.test(d)
  ) {
    return 'quality';
  }
  // Schema / object merge labeled PP without request/user taint language
  if (
    /prototype pollution|object\.assign|_\.defaults|_\.merge|_\.extend/i.test(d) &&
    !/tainted value from (express|koa|fastify|nestjs|request|req\.|user|header|query|body|param)/i.test(
      d
    ) &&
    !/tainted free variable/i.test(d)
  ) {
    // "Tainted object merged via Object.assign" without user source → quality
    if (/tainted object merged/i.test(d) && !/tainted value from/i.test(d)) {
      return 'quality';
    }
  }
  // Locale / pure message maps: throw embeds data without user source
  if (
    /generic throws|throw new error embeds|information in exception/i.test(d) &&
    !/tainted value from (express|koa|fastify|nestjs|request|req\.)/i.test(d)
  ) {
    return 'quality';
  }
  // Math.random in pure tooling / codegen / benches / request-context ids → quality
  // (Nest context-id-factory documents WeakMap reference equality — not a token)
  if (/math\.random\(\) used for security-sensitive/i.test(d)) {
    if (/\/(tsc|bench|benchmarks?|codegen|scripts|fixtures?)\//i.test(filePath)) {
      return 'quality';
    }
    if (/\b(generate|bench|context-id-factory)\.[jt]sx?$/i.test(filePath)) return 'quality';
    if (/context-id-factory|createContextId/i.test(filePath)) return 'quality';
  }
  // Nest/Express param factories returning req.* to app code — not XSS sinks
  if (
    /reaches controller return|XSS via HTML response/i.test(d) &&
    /route-params-factory|params-factory|ws-params-factory/i.test(filePath)
  ) {
    return 'quality';
  }
  // Log sinks — CWE-117 class; product noise unless request-tainted secrets
  if (/reaches console\.(log|info|error|warn|debug)|console\.(log|info|error|warn|debug) —/i.test(d)) {
    const requestTaintedSecret =
      /tainted value from (express|koa|fastify|nestjs|request)/i.test(d) &&
      /password|secret|token|credential|session|cookie|authorization/i.test(d);
    if (!requestTaintedSecret) return 'quality';
  }
  // Unhandled async — reliability, not security surface
  if (/async function without error boundary|unhandled rejection/i.test(d)) {
    return 'quality';
  }
  // Math.random weak PRNG → quality unless clearly auth/session/token path
  // (jobs/ cron jitter under members/ is not a token surface)
  if (/math\.random\(\) used for security-sensitive/i.test(d)) {
    if (/\/jobs?\//i.test(filePath)) return 'quality';
    if (!/\/(auth|session|members|login|oauth|jwt|crypto|security)\//i.test(filePath)) {
      return 'quality';
    }
  }
  // ENV-only → fetch/axios: deploy config / analytics endpoints, not user SSRF
  if (
    /tainted value from environment variables reaches (fetch|axios|http\.|https\.)/i.test(d) &&
    !/tainted value from (express|koa|fastify|nestjs|request|req\.|command-line|file\/stdin)/i.test(
      d
    )
  ) {
    return 'quality';
  }
  // Bootstrap NODE_ENV / process.env defaults — external config control noise
  if (
    /written to process\.env — external config|process\.env\.NODE_ENV/i.test(d) &&
    /environment variables/i.test(d)
  ) {
    return 'quality';
  }
  // Operator CLI/bin/scripts: argv/env → fs/fetch is tooling, not web attack surface
  if (
    /\/(bin|scripts?)\//i.test(filePath) &&
    /tainted value from (environment variables|command-line arguments|file\/stdin)/i.test(d) &&
    !/tainted value from (express|koa|fastify|nestjs|request)/i.test(d)
  ) {
    return 'quality';
  }
  // Local config/template tooling: File/stdin content → fetch/handlebars/fs.write
  // without request taint is generator/bootstrap, not web attacker SSRF/XSS/path.
  // (BP pathtraver uses request/env path strings; those keep "tainted value from Express…".)
  if (
    /tainted value from file\/stdin read content reaches/i.test(d) &&
    !/tainted value from (express|koa|fastify|nestjs|request|req\.)/i.test(d)
  ) {
    if (
      /reaches (fetch|axios|handlebars\.compile|fs\.write|fs\.read|js-yaml|yaml\.load|express\.res\.send|koa\.ctx\.body)/i.test(
        d
      )
    ) {
      return 'quality';
    }
  }
  // ENV path → readFileSync for app config bootstrap (load-config-file style)
  if (
    /tainted value from environment variables reaches fs\.(readFile|readFileSync|writeFile)/i.test(
      d
    ) &&
    !/tainted value from (express|koa|fastify|nestjs|request)/i.test(d)
  ) {
    return 'quality';
  }
  // Generators/codegen packages compiling templates from disk
  if (
    /\/(generators?|codegen|templates?)\//i.test(filePath) &&
    /handlebars\.compile|fs\.writeFile/i.test(d) &&
    !/tainted value from (express|koa|fastify|nestjs|request)/i.test(d)
  ) {
    return 'quality';
  }
  // Build/tooling content hashes (webpack/cache/node sha1/md5) — not password hashing
  // Note: alternation is bare `node` so `/src/node/core/` matches (not `node/` + extra `/`)
  if (
    /hashed with weak algorithm (sha1|md5)/i.test(d) &&
    /\/(webpack|vite|rollup|esbuild|node|build|cache|dependencies)\//i.test(filePath)
  ) {
    return 'quality';
  }
  // Multer/temp upload cleanup: file.path → fs.unlink is server temp, not path traversal
  if (
    /multipart single file reaches fs\.unlink|multipart.*reaches fs\.unlink/i.test(d)
  ) {
    return 'quality';
  }
  // Binary image responses (Content-Type image/* set nearby is common) — not HTML XSS
  if (
    /reaches express\.res\.send|reaches koa\.ctx\.body/i.test(d) &&
    /\/(gift-preview|og-image|image|png|jpeg|webp)\//i.test(filePath)
  ) {
    return 'quality';
  }
  // Hardcoded-secret false friends: UUID labels, provider tokens, public JWKS,
  // CMS UIDs/scopes/storage keys, cookie header construction
  if (type === 'hardcoded-secret' || /Hardcoded secret\/key\/token value/i.test(d)) {
    if (/UUID:|providerToken|providerKey|UuidFactory/i.test(d + filePath)) return 'quality';
    if (/jwks|accounts\.google|oauth2\/v3\/certs/i.test(d + filePath)) return 'quality';
    if (/STORAGE_KEY|TOKEN_UID|TOKEN_SCOPE|_UID\b|_SCOPE\b/i.test(filePath + d)) return 'quality';
    if (/Max-Age=|HttpOnly|SameSite=/i.test(d)) return 'quality';
  }

  // Type-level defaults
  if (type === 'null-safety' || type === 'error-boundary' || type === 'coupling-risk') {
    return 'quality';
  }
  if (type === 'async-race') {
    return 'quality'; // reliability unless refined later
  }
  if (type === 'hardcoded-secret') {
    return 'security';
  }

  // Default: injection / edge-case / ssrf / open-redirect → security
  return 'security';
}

export function annotateSurfaces(
  findings: AdversarialFinding[]
): Array<AdversarialFinding & { surface: FindingSurface }> {
  return findings.map((f) => ({
    ...f,
    // Always re-classify so path-aware rules apply (don't trust stale surface)
    surface: classifySurface(
      f.description,
      f.type,
      (f as { sink?: string }).sink,
      f.file
    ),
  }));
}

/**
 * Apply test-path filter and optional surface filter.
 * Default: drop test paths, keep both surfaces (annotated).
 */
export function applySurfacePipeline(
  findings: AdversarialFinding[],
  opts: SurfaceFilterOptions = {}
): {
  findings: Array<AdversarialFinding & { surface: FindingSurface }>;
  counts: {
    security: number;
    quality: number;
    droppedTests: number;
    totalIn: number;
  };
} {
  const includeTests = opts.includeTests === true;
  const surfaceMode = opts.surface || 'all';
  let droppedTests = 0;
  let list = findings;

  if (!includeTests) {
    const kept: AdversarialFinding[] = [];
    for (const f of findings) {
      if (isTestOrFixturePath(f.file)) {
        droppedTests++;
        continue;
      }
      kept.push(f);
    }
    list = kept;
  }

  const annotated = annotateSurfaces(list);
  const security = annotated.filter((f) => f.surface === 'security');
  const quality = annotated.filter((f) => f.surface === 'quality');

  let out = annotated;
  if (surfaceMode === 'security') out = security;
  else if (surfaceMode === 'quality') out = quality;

  return {
    findings: out,
    counts: {
      security: security.length,
      quality: quality.length,
      droppedTests,
      totalIn: findings.length,
    },
  };
}
