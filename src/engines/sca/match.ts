/**
 * SCA OSV matcher. Peer engine -- not NEBULA, not IaC.
 * Queries live POST https://api.osv.dev/v1/query. Does not read osv-gt.json.
 * Not wired into runPipeline / EngineFilter.
 */

import { Ecosystem, ParsedDep } from './types';

const OSV_QUERY = 'https://api.osv.dev/v1/query';
const CONCURRENCY = 6;
const ATTEMPTS = 4;

export interface MatchResult {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  ids: string[];
}

function mapEco(eco: Ecosystem): string {
  return eco === 'pypi' ? 'PyPI' : 'npm';
}

function isBlank(v: unknown): boolean {
  return typeof v !== 'string' || v.trim() === '';
}

function emptyResult(dep: ParsedDep): MatchResult {
  return {
    name: typeof dep?.name === 'string' ? dep.name : '',
    version: typeof dep?.version === 'string' ? dep.version : '',
    ecosystem: dep?.ecosystem,
    ids: [],
  };
}

function idsFromBody(data: unknown): string[] | null {
  if (!data || typeof data !== 'object') return null;
  const vulns = (data as { vulns?: unknown }).vulns;
  if (vulns == null) return [];
  if (!Array.isArray(vulns)) return null;
  const ids: string[] = [];
  const seen = new Set<string>();
  for (const v of vulns) {
    if (!v || typeof v !== 'object') continue;
    const id = (v as { id?: unknown }).id;
    if (typeof id === 'string' && id && !seen.has(id)) {
      seen.add(id);
      ids.push(id);
    }
    const aliases = (v as { aliases?: unknown }).aliases;
    if (Array.isArray(aliases)) {
      for (const a of aliases) {
        if (typeof a === 'string' && a && !seen.has(a)) {
          seen.add(a);
          ids.push(a);
        }
      }
    }
  }
  return ids;
}

async function queryOsv(name: string, version: string, ecosystem: Ecosystem): Promise<string[]> {
  const body = JSON.stringify({
    package: { name, ecosystem: mapEco(ecosystem) },
    version,
  });
  let lastErr: unknown;
  for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
    try {
      const res = await fetch(OSV_QUERY, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'vantage-sca-match/1',
        },
        body,
        signal: AbortSignal.timeout(60_000),
      });
      if (res.status === 429 || res.status >= 500) {
        lastErr = new Error('osv http ' + res.status);
        await new Promise((r) => setTimeout(r, 400 * (attempt + 1)));
        continue;
      }
      if (!res.ok) return [];
      let data: unknown;
      try {
        data = await res.json();
      } catch {
        return [];
      }
      const ids = idsFromBody(data);
      return ids == null ? [] : ids;
    } catch (e) {
      lastErr = e;
      await new Promise((r) => setTimeout(r, 400 * (attempt + 1)));
    }
  }
  void lastErr;
  return [];
}

export async function matchDep(dep: ParsedDep): Promise<MatchResult> {
  if (!dep || isBlank(dep.name) || isBlank(dep.version)) {
    return emptyResult(dep || ({ name: '', version: '', ecosystem: 'npm' } as ParsedDep));
  }
  const name = dep.name;
  const version = dep.version;
  const ecosystem = dep.ecosystem;
  const ids = await queryOsv(name.trim(), version.trim(), ecosystem);
  return { name, version, ecosystem, ids };
}

async function mapPool<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i]);
    }
  }
  const n = Math.max(1, Math.min(limit, items.length || 1));
  await Promise.all(Array.from({ length: n }, () => worker()));
  return out;
}

export async function matchDeps(deps: ParsedDep[]): Promise<MatchResult[]> {
  if (!Array.isArray(deps) || deps.length === 0) return [];
  return mapPool(deps, CONCURRENCY, matchDep);
}

