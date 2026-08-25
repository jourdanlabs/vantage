// VANTAGE Benchmark Harness — corpus management
// Handles cloning and verifying the benchmark corpora.

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { CorpusGroundTruth } from './ground-truth/schema';

export interface CorpusSpec {
  id: string;
  label: string;
  repo: string;
  /** Specific commit SHA to pin. 'latest' = don't verify, use whatever is cloned. */
  sha: string;
  localPath: string;
  /** Sub-directory within the repo to analyze (null = root) */
  targetSubdir: string | null;
}

export const CORPORA: CorpusSpec[] = [
  {
    id: 'nodegoat',
    label: 'OWASP/NodeGoat',
    repo: 'https://github.com/OWASP/NodeGoat.git',
    sha: 'latest',
    localPath: '/tmp/vantage-bench/nodegoat',
    targetSubdir: null,
  },
  {
    id: 'juice-shop',
    label: 'OWASP Juice Shop',
    repo: 'https://github.com/juice-shop/juice-shop.git',
    sha: 'latest',
    localPath: '/tmp/vantage-bench/juiceshop',
    targetSubdir: null,
  },
];

export interface CorpusWithGT extends CorpusSpec {
  groundTruth: CorpusGroundTruth;
  analysisPath: string;  // full path to run analysis against
}

/** Load ground truth catalog for a corpus ID */
export function loadGroundTruth(corpusId: string): CorpusGroundTruth {
  const gtFile = path.join(__dirname, 'ground-truth', `${corpusId}.json`);
  if (!fs.existsSync(gtFile)) {
    throw new Error(`Ground truth not found for corpus "${corpusId}": ${gtFile}`);
  }
  return JSON.parse(fs.readFileSync(gtFile, 'utf8')) as CorpusGroundTruth;
}

/** Ensure all corpora are cloned locally. Skips if already present. */
export function ensureCorpora(corpora: CorpusSpec[] = CORPORA): void {
  for (const corpus of corpora) {
    if (fs.existsSync(corpus.localPath)) {
      console.log(`  [corpus] ${corpus.id}: already present at ${corpus.localPath}`);
      continue;
    }

    console.log(`  [corpus] ${corpus.id}: cloning ${corpus.repo}...`);
    fs.mkdirSync(path.dirname(corpus.localPath), { recursive: true });
    execSync(`git clone --depth 1 "${corpus.repo}" "${corpus.localPath}"`, {
      stdio: 'inherit',
    });
    console.log(`  [corpus] ${corpus.id}: cloned.`);
  }
}

/** Get all corpora as CorpusWithGT (loads GTs, resolves analysis paths) */
export function getCorpora(ids?: string[]): CorpusWithGT[] {
  const all = ids
    ? CORPORA.filter(c => ids.includes(c.id))
    : CORPORA;

  return all
    .filter(c => fs.existsSync(c.localPath))
    .map(c => ({
      ...c,
      groundTruth: loadGroundTruth(c.id),
      analysisPath: c.targetSubdir
        ? path.join(c.localPath, c.targetSubdir)
        : c.localPath,
    }));
}
