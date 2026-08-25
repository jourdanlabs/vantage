/**
 * SCA manifest / lockfile parsers.
 * Parse only — no OSV matching, CVE lookup, scoring, or pipeline wiring.
 */

import * as fs from 'fs';
import * as path from 'path';
import { Ecosystem, ParsedDep, SourceKind } from './types';

const SKIP_DIRS = new Set<string>([
  'node_modules',
  '.git',
  'dist',
  'build',
  'vendor',
  '__pycache__',
]);

const LOCK_KINDS: ReadonlySet<SourceKind> = new Set([
  'package-lock.json',
  'Pipfile.lock',
]);

function dep(
  ecosystem: Ecosystem,
  name: string,
  version: string,
  sourceFile: string,
  sourceKind: SourceKind
): ParsedDep {
  return { ecosystem, name, version, sourceFile, sourceKind };
}

/** Concrete pin: no caret/tilde/star ranges, no git/url/workspace specs. */
export function isConcreteNpmVersion(raw: string): boolean {
  if (typeof raw !== 'string') return false;
  const s = raw.trim();
  if (!s) return false;
  if (/^(git\+|git:\/\/|github:|gitlab:|bitbucket:|https?:|ssh:|file:|workspace:|npm:|link:)/i.test(s)) {
    return false;
  }
  if (/^(latest|next|canary|beta|alpha|dev|main|master|HEAD)$/i.test(s)) return false;
  if (/[\s|*xX|^~<>]/.test(s)) return false;
  if (s.includes('||') || s.includes(' - ')) return false;
  return /^v?=?\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.-]+)?$/.test(s);
}

function stripNpmVersionPrefix(raw: string): string {
  return raw.trim().replace(/^v?=/, '');
}

export function parseNpmPackageJson(content: string, sourceFile: string): ParsedDep[] {
  let json: any;
  try {
    json = JSON.parse(content);
  } catch {
    return [];
  }
  if (!json || typeof json !== 'object' || Array.isArray(json)) return [];

  const out: ParsedDep[] = [];
  const seen = new Set<string>();
  const blocks = [json.dependencies, json.optionalDependencies];
  for (const block of blocks) {
    if (!block || typeof block !== 'object' || Array.isArray(block)) continue;
    for (const [name, version] of Object.entries(block)) {
      if (!name || typeof version !== 'string') continue;
      if (!isConcreteNpmVersion(version)) continue;
      if (seen.has(name)) continue;
      seen.add(name);
      out.push(dep('npm', name, stripNpmVersionPrefix(version), sourceFile, 'package.json'));
    }
  }
  return out;
}

function npmNameFromPackagesKey(key: string): string | undefined {
  if (!key) return undefined;
  const marker = 'node_modules/';
  const idx = key.lastIndexOf(marker);
  if (idx < 0) return undefined;
  const rest = key.slice(idx + marker.length);
  return rest || undefined;
}

export function parseNpmPackageLock(content: string, sourceFile: string): ParsedDep[] {
  let json: any;
  try {
    json = JSON.parse(content);
  } catch {
    return [];
  }
  if (!json || typeof json !== 'object') return [];
  const ver = json.lockfileVersion;
  if (ver !== 2 && ver !== 3) return [];
  const packages = json.packages;
  if (!packages || typeof packages !== 'object' || Array.isArray(packages)) return [];

  const out: ParsedDep[] = [];
  for (const [key, entry] of Object.entries(packages)) {
    if (key === '') continue;
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const rec = entry as { name?: unknown; version?: unknown; dev?: unknown; devOptional?: unknown };
    if (rec.dev === true || rec.devOptional === true) continue;
    const version = typeof rec.version === 'string' ? rec.version.trim() : '';
    const name =
      (typeof rec.name === 'string' && rec.name.trim()) ||
      npmNameFromPackagesKey(key);
    if (!name || !version) continue;
    out.push(dep('npm', name, version, sourceFile, 'package-lock.json'));
  }
  return out;
}

const REQ_NAME_EQ = /^([^\s=#]+?)(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)/;

export function parsePypiRequirements(content: string, sourceFile: string): ParsedDep[] {
  const out: ParsedDep[] = [];
  const seen = new Set<string>();
  for (const rawLine of content.split(/\r?\n/)) {
    const noComment = rawLine.split('#')[0].trim();
    if (!noComment) continue;
    if (noComment.startsWith('-')) continue;
    const beforeMarker = noComment.split(';')[0].trim();
    const m = beforeMarker.match(REQ_NAME_EQ);
    if (!m) continue;
    const name = m[1];
    const version = m[2];
    if (!name || !version) continue;
    if (seen.has(name)) continue;
    seen.add(name);
    out.push(dep('pypi', name, version, sourceFile, 'requirements.txt'));
  }
  return out;
}

export function parsePipfileLock(content: string, sourceFile: string): ParsedDep[] {
  let json: any;
  try {
    json = JSON.parse(content);
  } catch {
    return [];
  }
  if (!json || typeof json !== 'object') return [];
  const defaults = json.default;
  if (!defaults || typeof defaults !== 'object' || Array.isArray(defaults)) return [];

  const out: ParsedDep[] = [];
  for (const [name, entry] of Object.entries(defaults)) {
    if (!name) continue;
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const raw = (entry  as { version?: unknown }).version;
    if (typeof raw !== 'string') continue;
    const m = raw.trim().match(/^==\s*(.+)$/);
    if (!m) continue;
    const version = m[1].trim();
    if (!version) continue;
    out.push(dep('pypi', name, version, sourceFile, 'Pipfile.lock'));
  }
  return out;
}

function walkFiles(dir: string, acc: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (SKIP_DIRS.has(ent.name)) continue;
      walkFiles(full, acc);
      continue;
    }
    if (!ent.isFile()) continue;
    if (
      ent.name === 'package.json' ||
      ent.name === 'package-lock.json' ||
      ent.name === 'requirements.txt' ||
      ent.name === 'Pipfile.lock'
    ) {
      acc.push(full);
    }
  }
}

function readUtf8(file: string): string | null {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

function mergeLockWins(deps: ParsedDep[]): ParsedDep[] {
  const map = new Map<string, ParsedDep>();
  for (const d of deps) {
    const key = `${path.dirname(d.sourceFile)}\0${d.ecosystem}\0${d.name}`;
    const existing = map.get(key);
    if (!existing) {
      map.set(key, d);
      continue;
    }
    const incomingLock = LOCK_KINDS.has(d.sourceKind);
    const existingLock = LOCK_KINDS.has(existing.sourceKind);
    if (incomingLock && !existingLock) map.set(key, d);
  }
  return [...map.values()];
}

export function parseManifestsInDir(root: string): ParsedDep[] {
  const files: string[] = [];
  walkFiles(root, files);
  const collected: ParsedDep[] = [];
  for (const file of files) {
    const base = path.basename(file);
    const content = readUtf8(file);
    if (content == null) continue;
    if (base === 'package.json') collected.push(...parseNpmPackageJson(content, file));
    else if (base === 'package-lock.json') collected.push(...parseNpmPackageLock(content, file));
    else if (base === 'requirements.txt') collected.push(...parsePypiRequirements(content, file));
    else if (base === 'Pipfile.lock') collected.push(...parsePipfileLock(content, file));
  }
  return mergeLockWins(collected);
}
