// VANTAGE COSMIC Pipeline — Orchestrator
// Runs METEOR → NOVA → ECLIPSE → PULSAR → AURORA in sequence

export { runMETEOR } from './meteor';
export { runNOVA } from './nova';
export { runECLIPSE } from './eclipse';
export { runPULSAR } from './pulsar';
export { runAURORA } from './aurora';

import { runMETEOR } from './meteor';
import { runNOVA } from './nova';
import { runECLIPSE } from './eclipse';
import { runPULSAR } from './pulsar';
import { runAURORA } from './aurora';
import { VantageReport } from '../types';

export type EngineFilter = 'METEOR' | 'NOVA' | 'ECLIPSE' | 'PULSAR' | 'AURORA' | null;

export async function runPipeline(
  targetPath: string,
  engineFilter: EngineFilter = null,
  onProgress?: (engine: string, msg: string) => void,
  threshold = 0.80
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

  const nova = await runNOVA(meteor, progress('NOVA'));
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

  const eclipse = await runECLIPSE(meteor, nova, progress('ECLIPSE'));
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
