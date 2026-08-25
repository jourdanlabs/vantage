// VANTAGE COSMIC Pipeline — Orchestrator
// Runs METEOR → NOVA → ECLIPSE → PULSAR → (NEBULA?) → (CRUCIBLE) → AURORA in sequence.
//
// NEBULA is the semantic/taint engine. It's opt-in via `opts.semantic` because
// it's slower (seconds instead of milliseconds) and its v0 catalog is narrow.
// When enabled, its findings are merged into PULSAR's adversarialFindings
// before AURORA runs, so they flow through scoring, get_findings, and the
// fix loop identically to pattern-based PULSAR findings — no downstream
// changes required.

export { runMETEOR } from './meteor';
export { runNOVA } from './nova';
export { runECLIPSE } from './eclipse';
export { runPULSAR } from './pulsar';
export { runAURORA } from './aurora';
export { runCrucible } from './crucible';

import { runMETEOR } from './meteor';
import { runNOVA } from './nova';
import { runECLIPSE } from './eclipse';
import { runPULSAR } from './pulsar';
import { runAURORA } from './aurora';
import { runNebula, TaintFinding } from './nebula';
import { runCrucible, CrucibleFinding } from './crucible';
import { applySurfacePipeline, classifySurface } from './surface';
import { VantageReport, AdversarialFinding } from '../types';

export type EngineFilter = 'METEOR' | 'NOVA' | 'ECLIPSE' | 'PULSAR' | 'NEBULA' | 'CRUCIBLE' | 'AURORA' | null;

export interface PipelineOptions {
  semantic?: boolean;
  /**
   * Bench/proctor path: METEOR → PULSAR → (NEBULA) → light AURORA.
   * Skips NOVA + ECLIPSE graph work. Required for BenchProctor normal (~40k
   * files) where companion-free case sets still thrash full COSMIC.
   */
  benchFast?: boolean;
  /**
   * Include test/spec/fixture paths (default false for product scans).
   * BenchProctor cases are not under test/ — leave false there too.
   */
  includeTests?: boolean;
  /** Report surface filter. Findings are always classified; this only drops rows. */
  surface?: 'security' | 'quality' | 'all';
}

export async function runPipeline(
  targetPath: string,
  engineFilter: EngineFilter = null,
  onProgress?: (engine: string, msg: string) => void,
  threshold = 0.80,
  opts: PipelineOptions = {}
): Promise<VantageReport> {
  const progress = (engine: string) => (msg: string) => onProgress?.(engine, msg);
  const stubAurora = (summary: string) => ({
    score: 0, verdict: 'REJECTED' as const, topIssues: [], fixes: [], summary,
    breakdown: { complexityScore: 0, dependencyScore: 0, riskScore: 0, adversarialScore: 0 },
    threshold,
  });
  const stubMeteorUnsupported = { count: 0, extensions: [], filePaths: [] };

  const meteor = await runMETEOR(targetPath, progress('METEOR'));
  if (engineFilter === 'METEOR') {
    return {
      target: targetPath,
      timestamp: new Date().toISOString(),
      meteor,
      nova: { causalChains: [], dependencyGraph: {}, circularDeps: [], couplingIssues: [], godModules: [] },
      eclipse: { riskScores: {}, highRisk: [], medRisk: [], estimatedBugProbability: 0 },
      pulsar: { adversarialFindings: [], missingGuards: [], recommendations: [] },
      aurora: stubAurora('METEOR only run'),
    };
  }

  const benchFast = opts.benchFast === true || process.env.VANTAGE_BENCH_FAST === '1';

  let nova: Awaited<ReturnType<typeof runNOVA>>;
  let eclipse: Awaited<ReturnType<typeof runECLIPSE>>;

  if (benchFast) {
    progress('NOVA')('skipped (VANTAGE_BENCH_FAST)');
    progress('ECLIPSE')('skipped (VANTAGE_BENCH_FAST)');
    nova = { causalChains: [], dependencyGraph: {}, circularDeps: [], couplingIssues: [], godModules: [] };
    eclipse = { riskScores: {}, highRisk: [], medRisk: [], estimatedBugProbability: 0 };
  } else {
    nova = await runNOVA(meteor, progress('NOVA'));
    if (engineFilter === 'NOVA') {
      return {
        target: targetPath,
        timestamp: new Date().toISOString(),
        meteor,
        nova,
        eclipse: { riskScores: {}, highRisk: [], medRisk: [], estimatedBugProbability: 0 },
        pulsar: { adversarialFindings: [], missingGuards: [], recommendations: [] },
        aurora: stubAurora('NOVA only run'),
      };
    }

    eclipse = await runECLIPSE(meteor, nova, progress('ECLIPSE'));
    if (engineFilter === 'ECLIPSE') {
      return {
        target: targetPath,
        timestamp: new Date().toISOString(),
        meteor,
        nova,
        eclipse,
        pulsar: { adversarialFindings: [], missingGuards: [], recommendations: [] },
        aurora: stubAurora('ECLIPSE only run'),
      };
    }
  }

  const pulsar = await runPULSAR(meteor, eclipse, progress('PULSAR'));
  if (engineFilter === 'PULSAR') {
    return {
      target: targetPath,
      timestamp: new Date().toISOString(),
      meteor,
      nova,
      eclipse,
      pulsar,
      aurora: stubAurora('PULSAR only run'),
    };
  }

  // NEBULA — semantic / taint engine. Opt-in.
  //
  // Kaioken merge policy (2026-08-02):
  // When --semantic is on, NEBULA owns *security* discrimination for sinks it
  // models (injection / taint). Pattern-PULSAR findings of type `injection`
  // and JSON.parse `error-boundary` noise are dropped for files NEBULA
  // analyzed — otherwise pattern FPs drown allowlist-safe twins and deserial
  // safe JSON.parse cases (BenchProctor loss mode). Secrets / async / null
  // patterns stay from PULSAR.
  if (opts.semantic || engineFilter === 'NEBULA') {
    const progressNebula = progress('NEBULA');
    progressNebula('running intraprocedural taint analysis...');
    const nebula = await runNebula(targetPath);
    progressNebula(`done: ${nebula.findings.length} finding(s) in ${nebula.filesAnalyzed} file(s), ${nebula.durationMs}ms`);

    // Include full description so multiple NEBULA findings on the same line
    // are not collapsed (Kaioken LIV). Slice(0,96) was too short after the
    // "[NEBULA] " prefix — inject vs db.execute.unchecked-return shared 98
    // chars and dropped ~40% of CWE-252 family TPs (Kaioken LV).
    const keyOf = (
      file: string,
      line: number | undefined,
      type: string,
      desc?: string
    ) => `${file}:${line ?? 0}:${type}:${desc || ''}`;

    // Files NEBULA successfully walked (any language count > 0 implies those paths).
    // We suppress pattern security noise on every absolute path that appears in
    // NEBULA findings OR that is a JS/TS file under target (NEBULA walks all of them).
    // Conservative: drop pattern injection + JSON.parse-error-boundary globally
    // under semantic mode — NEBULA is the security engine for those classes.
    const before = pulsar.adversarialFindings.length;
    pulsar.adversarialFindings = pulsar.adversarialFindings.filter((f) => {
      // Keep pattern-only classes NEBULA does not model yet ($where, ReDoS).
      // Drop eval/generic injection — NEBULA owns those with sanitizer awareness.
      if (f.type === 'injection') {
        // $where / ReDoS stay as JS pattern-only classes. Python nosql is
        // modeled in the Python catalog — keeping $where on .py files is a
        // 100% FPR spray (safe twins also contain $where).
        if (/\$where/i.test(f.description) && /\.py$/i.test(f.file || '')) return false;
        if (/\$where|redos|new\s+regexp/i.test(f.description)) return true;
        return false;
      }
      if (f.type === 'error-boundary' && /JSON\.parse/i.test(f.description)) {
        return false; // bare JSON.parse is not a deserial RCE finding
      }
      return true;
    });
    const dropped = before - pulsar.adversarialFindings.length;

    const existingKeys = new Set(
      pulsar.adversarialFindings.map(f => keyOf(f.file, f.line, f.type, f.description))
    );
    for (const tf of nebula.findings) {
      const adv = taintToAdversarial(tf);
      const key = keyOf(adv.file, adv.line, adv.type, adv.description);
      if (existingKeys.has(key)) continue;
      pulsar.adversarialFindings.push(adv);
      existingKeys.add(key);
    }
    progressNebula(
      `merge: dropped ${dropped} pattern security FP-candidates; +${nebula.findings.length} NEBULA; total ${pulsar.adversarialFindings.length}`
    );

    if (engineFilter === 'NEBULA') {
      applySurfaces(pulsar, opts, progress('NEBULA'));
      return {
        target: targetPath,
        timestamp: new Date().toISOString(),
        meteor,
        nova,
        eclipse,
        pulsar,
        aurora: stubAurora('NEBULA only run'),
      };
    }
  }

  // CRUCIBLE — structural IaC / Docker rules. Peer of NEBULA, not a taint frontend.
  // Declared-dark: Kubernetes, cross-file / cross-module tracing, taint.
  // Cheap: skip work when the tree has no .tf / Dockerfile. Always available
  // as engineFilter === 'CRUCIBLE'. Merges into PULSAR findings like NEBULA.
  if (engineFilter === 'CRUCIBLE' || engineFilter === null) {
    const progressCrucible = progress('CRUCIBLE');
    progressCrucible('running structural IaC/Docker rules...');
    const crucible = await runCrucible(targetPath);
    progressCrucible(
      `done: ${crucible.findings.length} finding(s) in ${crucible.filesAnalyzed} file(s), ${crucible.durationMs}ms`
    );
    const existing = new Set(
      pulsar.adversarialFindings.map(f => `${f.file}:${f.line ?? 0}:${f.description || ''}`)
    );
    for (const cf of crucible.findings) {
      const adv = crucibleToAdversarial(cf);
      const key = `${adv.file}:${adv.line ?? 0}:${adv.description || ''}`;
      if (existing.has(key)) continue;
      pulsar.adversarialFindings.push(adv);
      existing.add(key);
    }
    if (engineFilter === 'CRUCIBLE') {
      applySurfaces(pulsar, opts, progress('CRUCIBLE'));
      return {
        target: targetPath,
        timestamp: new Date().toISOString(),
        meteor,
        nova,
        eclipse,
        pulsar,
        aurora: stubAurora('CRUCIBLE only run'),
      };
    }
  }

  // Surface split + test-path defaults (always — security/quality taxonomy)
  applySurfaces(pulsar, opts, progress('PULSAR'));

  const aurora = await runAURORA(meteor, nova, eclipse, pulsar, progress('AURORA'), threshold);

  return {
    target: targetPath,
    timestamp: new Date().toISOString(),
    meteor,
    nova,
    eclipse,
    pulsar,
    aurora
  };
}

/**
 * Convert a NEBULA TaintFinding to the PULSAR AdversarialFinding shape so it
 * can live in the same list without downstream consumers needing to know the
 * difference.  We prepend "[NEBULA]" to the description so UI displays and
 * logs make the provenance obvious.
 */
function taintToAdversarial(tf: TaintFinding): AdversarialFinding {
  // TaintFinding.type may include categories not in AdversarialFinding's
  // type union (e.g. 'open-redirect', 'ssrf'). Map those to the closest
  // existing category; v1 AdversarialFinding type union is narrow but
  // covers the common cases.
  const typeMap: Record<string, AdversarialFinding['type']> = {
    'injection': 'injection',
    'open-redirect': 'edge-case',
    'ssrf': 'edge-case',
  };
  const mappedType = typeMap[tf.type] ?? 'injection';
  const description = `[NEBULA] ${tf.description}`;
  return {
    file: tf.file,
    line: tf.line,
    type: mappedType,
    severity: tf.severity,
    description,
    testCase: tf.testCase,
    surface: classifySurface(description, mappedType, tf.sink, tf.file),
  };
}


function crucibleToAdversarial(cf: CrucibleFinding): AdversarialFinding {
  const description = `[CRUCIBLE] ${cf.ruleId}: ${cf.message}`;
  return {
    file: cf.file,
    line: cf.startLine,
    type: 'edge-case',
    severity: cf.severity,
    description,
    testCase: `${cf.ruleId} at ${cf.uri}:${cf.startLine}`,
    surface: classifySurface(description, 'edge-case', cf.resourceType, cf.file),
  };
}

/** Classify surfaces, drop test paths by default, optional surface filter. */
function applySurfaces(
  pulsar: { adversarialFindings: AdversarialFinding[] },
  opts: PipelineOptions,
  onProgress?: (msg: string) => void
): void {
  const { findings, counts } = applySurfacePipeline(pulsar.adversarialFindings, {
    // Default: drop test/spec paths. BP case files are not under test/.
    includeTests: opts.includeTests === true,
    // Keep both surfaces in the report (scorers/CWE tags need quality rows too).
    // CLI may pass surface=security for product demos.
    surface: opts.surface || 'all',
  });
  pulsar.adversarialFindings = findings;
  onProgress?.(
    `surfaces: security=${counts.security} quality=${counts.quality} droppedTests=${counts.droppedTests} (in=${counts.totalIn})`
  );
}
