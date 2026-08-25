// VANTAGE MCP — content-hash-keyed report cache in ~/.vantage/cache/

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as os from 'os';
import { VantageReport } from '../types';

const CACHE_DIR = path.join(os.homedir(), '.vantage', 'cache');

function ensureCacheDir(): void {
  if (!fs.existsSync(CACHE_DIR)) {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
  }
}

/**
 * Compute a content hash for a directory by hashing all file mtimes + sizes.
 * Fast: doesn't read file contents. Invalidates on any file change.
 */
export function computeDirectoryHash(targetPath: string, options: Record<string, unknown> = {}): string {
  const hash = crypto.createHash('sha256');

  // Hash the options object
  hash.update(JSON.stringify(options));

  function walkDir(dir: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    // Sort for determinism
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      // Skip node_modules, .git, dist, coverage
      if (entry.isDirectory()) {
        if (['node_modules', '.git', 'dist', 'coverage', '.scannerwork'].includes(entry.name)) continue;
        walkDir(fullPath);
      } else if (entry.isFile()) {
        try {
          const stat = fs.statSync(fullPath);
          hash.update(`${fullPath}:${stat.mtimeMs}:${stat.size}\n`);
        } catch {
          // skip unreadable files
        }
      }
    }
  }

  const abs = path.resolve(targetPath);
  if (fs.existsSync(abs) && fs.statSync(abs).isDirectory()) {
    walkDir(abs);
  } else if (fs.existsSync(abs)) {
    const stat = fs.statSync(abs);
    hash.update(`${abs}:${stat.mtimeMs}:${stat.size}\n`);
  }

  return hash.digest('hex').slice(0, 16);
}

export interface CacheEntry {
  reportId: string;
  report: VantageReport;
  cachedAt: string;
  targetPath: string;
}

export function getCachedReport(hash: string): CacheEntry | null {
  ensureCacheDir();
  const cachePath = path.join(CACHE_DIR, `${hash}.json`);
  if (!fs.existsSync(cachePath)) return null;

  try {
    const raw = fs.readFileSync(cachePath, 'utf8');
    return JSON.parse(raw) as CacheEntry;
  } catch {
    return null;
  }
}

export function setCachedReport(hash: string, entry: CacheEntry): void {
  ensureCacheDir();
  const cachePath = path.join(CACHE_DIR, `${hash}.json`);
  fs.writeFileSync(cachePath, JSON.stringify(entry));
}

export function getReportById(reportId: string): CacheEntry | null {
  ensureCacheDir();
  try {
    const files = fs.readdirSync(CACHE_DIR).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const raw = fs.readFileSync(path.join(CACHE_DIR, file), 'utf8');
        const entry = JSON.parse(raw) as CacheEntry;
        if (entry.reportId === reportId) return entry;
      } catch {
        continue;
      }
    }
  } catch {
    // cache dir doesn't exist yet
  }
  return null;
}

export function clearCache(): void {
  ensureCacheDir();
  const files = fs.readdirSync(CACHE_DIR).filter(f => f.endsWith('.json'));
  for (const file of files) {
    fs.unlinkSync(path.join(CACHE_DIR, file));
  }
}
