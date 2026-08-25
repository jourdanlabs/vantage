// Stable finding IDs keyed on content, not run order.
//
// The old implementation hashed `source + JSON.stringify(obj)` with a
// non-cryptographic string hash, and finding IDs drifted if the engines
// iterated files in different order on consecutive runs.  That broke any
// caller (notably verify_fix) that tried to check whether a prior finding
// was still present after a patch.
//
// New scheme: SHA1 of `<source>|<normalizedFile>|<line>|<type>|<description>`.
// Normalizing the file path ensures IDs survive `cp -r` into a temp working
// copy — a finding at `/tmp/vantage-verify-abc/app/foo.js` has the same ID
// as the original at `/Users/me/app/foo.js`.

import * as crypto from 'crypto';
import * as path from 'path';

export type FindingSource = 'PULSAR' | 'NOVA' | 'ECLIPSE';

export interface FindingKey {
  source: FindingSource;
  file: string;
  line?: number;
  type: string;
  description: string;
}

/**
 * Strip any target-path prefix so IDs are stable across filesystem locations.
 * Falls back to just the basename segments if path.relative would produce `..`.
 */
function normalizeFile(file: string, targetPath?: string): string {
  if (!file) return '';
  const abs = path.isAbsolute(file) ? file : path.resolve(file);
  if (targetPath) {
    const rel = path.relative(path.resolve(targetPath), abs);
    if (rel && !rel.startsWith('..')) {
      return rel.split(path.sep).join('/');
    }
  }
  // Take the trailing segments after any known top-level src/app/lib marker
  // so paths like `/a/b/c/app/foo.js` and `/tmp/x/app/foo.js` both normalize
  // to `app/foo.js`.
  const parts = abs.split(/[\\/]/);
  const markers = ['src', 'app', 'lib', 'routes', 'packages'];
  for (let i = 0; i < parts.length; i++) {
    if (markers.includes(parts[i])) {
      return parts.slice(i).join('/');
    }
  }
  return path.basename(abs);
}

export function computeFindingId(key: FindingKey, targetPath?: string): string {
  const canonical = [
    key.source,
    normalizeFile(key.file, targetPath),
    key.line ?? 0,
    (key.type || '').toLowerCase(),
    (key.description || '').trim(),
  ].join('|');
  const hash = crypto.createHash('sha1').update(canonical).digest('hex').slice(0, 12);
  return `${key.source.toLowerCase()}_${hash}`;
}
