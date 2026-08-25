// SCA matcher positive control. Run with:
//   npx ts-node src/engines/sca/match.test.ts
//
// POSITIVE CONTROL ONLY. If any check fails, exit 1 and do not score the hold-out.
// Reads osv-gt.json here only to pick a zero-hit row for the offset control.
// match.ts must not import that file.

import * as fs from 'fs';
import * as path from 'path';
import { matchDep } from './match';
import { ParsedDep } from './types';

const REPO = path.resolve(__dirname, '..', '..', '..');
const HOLDOUT = path.join(REPO, 'receipts', 'sca-v1-holdout-2026-08-18q');
const GT_PATH = path.join(HOLDOUT, 'osv-gt.json');

let pass = 0;
let fail = 0;
const controlLog: Array<{ name: string; passed: boolean; detail?: unknown }> = [];

function check(name: string, cond: boolean, detail?: unknown): void {
  controlLog.push({ name, passed: cond, detail });
  if (cond) {
    console.log('  \u2713 ' + name);
    pass++;
  } else {
    console.log('  \u2717 ' + name);
    if (detail !== undefined) console.log('    ', detail);
    fail++;
  }
}

function dep(partial: Pick<ParsedDep, 'name' | 'version' | 'ecosystem'>): ParsedDep {
  return {
    ecosystem: partial.ecosystem,
    name: partial.name,
    version: partial.version,
    sourceFile: 'positive-control',
    sourceKind: partial.ecosystem === 'pypi' ? 'requirements.txt' : 'package.json',
  };
}

async function main(): Promise<void> {
  {
    const r = await matchDep(dep({ ecosystem: 'npm', name: '!!!not-a-pkg!!!', version: '1.0.0' }));
    check(
      'corrupt name !!!not-a-pkg!!! + 1.0.0 -> ids []',
      Array.isArray(r.ids) && r.ids.length === 0,
      r
    );
  }

  {
    const r = await matchDep(
      dep({ ecosystem: 'npm', name: 'sca-fixture-leftpad', version: 'not-a-version' })
    );
    check(
      'corrupt version not-a-version + leftpad-like fake -> ids []',
      Array.isArray(r.ids) && r.ids.length === 0,
      r
    );
  }

  {
    const gt = JSON.parse(fs.readFileSync(GT_PATH, 'utf8'));
    const results: Array<{
      ecosystem: 'npm' | 'pypi';
      name: string;
      version: string;
      vuln_ids?: string[];
      vuln_count?: number;
    }> = gt.results || gt.deps || [];
    const zero = results.find(
      (row) =>
        (row.vuln_count === 0 || !row.vuln_count) &&
        Array.isArray(row.vuln_ids) &&
        row.vuln_ids.length === 0 &&
        typeof row.name === 'string' &&
        row.name &&
        typeof row.version === 'string' &&
        row.version
    );
    if (!zero) {
      check('hold-out has a zero-hit row for offset control', false, 'no zero-hit row in osv-gt.json');
    } else {
      const offsetVer = '0.0.0-sca-offset';
      const r = await matchDep(
        dep({ ecosystem: zero.ecosystem, name: zero.name, version: offsetVer })
      );
      const closed = Array.isArray(r.ids) && r.ids.length === 0;
      check(
        'one-version offset on sealed zero-hit row at 0.0.0-sca-offset -> ids []',
        closed,
        closed
          ? { ids: r.ids, name: r.name, version: r.version }
          : {
              fail_closed: true,
              note: 'live OSV returned hits on the offset version; do not tweak matcher to pass',
              sealed_zero: { ecosystem: zero.ecosystem, name: zero.name, version: zero.version },
              queried: { name: r.name, version: r.version, ids: r.ids },
            }
      );
    }
  }

  const logPath = path.join(HOLDOUT, 'CONTROL-RUN.json');
  const logDoc = {
    kind: 'sca-v1-positive-control-run',
    holdout: path.basename(HOLDOUT),
    written_at: new Date().toISOString(),
    pass,
    fail,
    note: 'Positive control only. Not a GT query. Not a score. Pan can recount from this file without a live OSV replay.',
    checks: controlLog,
  };
  fs.writeFileSync(logPath, JSON.stringify(logDoc, null, 2) + '\n');
  console.log('wrote', logPath);
  console.log('\n' + pass + ' pass, ' + fail + ' fail');
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
