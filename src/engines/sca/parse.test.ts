// SCA parser checks. Run with:
//   npx ts-node src/engines/sca/parse.test.ts
//
// Parse only — no OSV matching, CVE lookup, scoring, or pipeline wiring.

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  parseManifestsInDir,
  parseNpmPackageJson,
  parseNpmPackageLock,
  parsePipfileLock,
  parsePypiRequirements,
} from './parse';
import { ParsedDep } from './types';

const FIXTURES = path.join(__dirname, 'fixtures');

let pass = 0;
let fail = 0;

function check(name: string, cond: boolean, detail?: unknown): void {
  if (cond) {
    console.log(`  ✓ ${name}`);
    pass++;
  } else {
    console.log(`  ✗ ${name}`);
    if (detail !== undefined) console.log('    ', detail);
    fail++;
  }
}

function names(deps: ParsedDep[]): string[] {
  return deps.map((d) => d.name).sort();
}

function findName(deps: ParsedDep[], name: string): ParsedDep | undefined {
  return deps.find((d) => d.name === name);
}

{
  const pkg = fs.readFileSync(path.join(FIXTURES, 'npm-mini', 'package.json'), 'utf8');
  const deps = parseNpmPackageJson(pkg, 'package.json');
  check('package.json keeps concrete pin', findName(deps, 'sca-fixture-leftpad')?.version === '9.9.9');
  check('package.json keeps optionalDependencies pin', findName(deps, 'sca-fixture-optional')?.version === '3.1.4');
  check(
    'package.json skips caret/star/git',
    !findName(deps, 'sca-fixture-caret') &&
      !findName(deps, 'sca-fixture-star') &&
      !findName(deps, 'sca-fixture-git')
  );
  check(
    'package.json sourceKind',
    deps.every((d) => d.ecosystem === 'npm' && d.sourceKind === 'package.json')
  );
}

{
  const inline = JSON.stringify({
    dependencies: {
      'sca-fixture-tilde': '~1.2.3',
      'sca-fixture-ge': '>=1.0.0',
      'sca-fixture-pin': '1.2.3',
    },
  });
  const deps = parseNpmPackageJson(inline, 'package.json');
  check('package.json skips tilde and range', names(deps).join(',') === 'sca-fixture-pin');
}

{
  const lock = fs.readFileSync(path.join(FIXTURES, 'npm-mini', 'package-lock.json'), 'utf8');
  const deps = parseNpmPackageLock(lock, 'package-lock.json');
  check('lock skips empty root', !deps.some((d) => d.name === 'sca-fixture-' + 'npm' + '-mini'));
  check('lock emits leftpad 1.0.0', findName(deps, 'sca-fixture-leftpad')?.version === '1.0.0');
  check('lock emits optional 3.1.4', findName(deps, 'sca-fixture-optional')?.version === '3.1.4');
  check('lock emits named trans 0.9.0', findName(deps, 'sca-fixture-trans')?.version === '0.9.0');
  check('lock sourceKind', deps.every((d) => d.sourceKind === 'package-lock.json' && d.ecosystem === 'npm'));
}

{
  const v1 = JSON.stringify({
    lockfileVersion: 1,
    dependencies: { 'sca-fixture-old': { version: '1.0.0' } },
    packages: { 'node_modules/sca-fixture-old': { version: '1.0.0' } },
  });
  check('lock ignores lockfileVersion 1', parseNpmPackageLock(v1, 'package-lock.json').length === 0);
}

{
  const req = fs.readFileSync(path.join(FIXTURES, 'pypi-mini', 'requirements.txt'), 'utf8');
  const deps = parsePypiRequirements(req, 'requirements.txt');
  check('requirements keeps == pin', findName(deps, 'sca-fixture-pyleft')?.version === '0.1.0');
  check('requirements keeps marker pin', findName(deps, 'sca-fixture-pyopt')?.version === '1.4.0');
  check(
    'requirements skips comments -r -e unpinned extras-only range',
    !findName(deps, 'sca-fixture-unpinned') &&
      !findName(deps, 'sca-fixture-range') &&
      !findName(deps, 'pytest') &&
      deps.length === 3
  );
}

{
  const lock = fs.readFileSync(path.join(FIXTURES, 'pypi-mini', 'Pipfile.lock'), 'utf8');
  const deps = parsePipfileLock(lock, 'Pipfile.lock');
  check('pipfile default strips ==', findName(deps, 'sca-fixture-pyleft')?.version === '0.2.0');
  check('pipfile default emits lock-only', findName(deps, 'sca-fixture-pylockonly')?.version === '4.0.1');
  check('pipfile skips develop', !findName(deps, 'sca-fixture-pydev'));
  check('pipfile sourceKind', deps.every((d) => d.sourceKind === 'Pipfile.lock' && d.ecosystem === 'pypi'));
}

{
  const deps = parseManifestsInDir(path.join(FIXTURES, 'npm-mini'));
  const left = findName(deps, 'sca-fixture-leftpad');
  check('dir: lock version wins over package.json pin', left?.version === '1.0.0' && left?.sourceKind === 'package-lock.json');
  check('dir: caret never appears', !findName(deps, 'sca-fixture-caret'));
  check('dir: lock-only trans included', findName(deps, 'sca-fixture-trans')?.version === '0.9.0');
  check('dir: optional from lock', findName(deps, 'sca-fixture-optional')?.version === '3.1.4');
}

{
  const deps = parseManifestsInDir(path.join(FIXTURES, 'pypi-mini'));
  const pyleft = findName(deps, 'sca-fixture-pyleft');
  check('dir: lock version wins over requirements pin', pyleft?.version === '0.2.0' && pyleft?.sourceKind === 'Pipfile.lock');
  check('dir: requirements-only pin kept', findName(deps, 'sca-fixture-pyopt')?.version === '1.4.0');
  check('dir: lock-only kept', findName(deps, 'sca-fixture-pylockonly')?.version === '4.0.1');
  check('dir: develop not merged', !findName(deps, 'sca-fixture-pydev'));
}

{
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sca-walk-'));
  try {
    fs.mkdirSync(path.join(tmp, 'node_modules', 'hidden'), { recursive: true });
    fs.mkdirSync(path.join(tmp, '.git'), { recursive: true });
    fs.mkdirSync(path.join(tmp, 'dist'), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, 'node_modules', 'hidden', 'package.json'),
      JSON.stringify({ dependencies: { 'sca-fixture-hidden': '1.0.0' } })
    );
    fs.writeFileSync(
      path.join(tmp, '.git', 'package.json'),
      JSON.stringify({ dependencies: { 'sca-fixture-gitdir': '1.0.0' } })
    );
    fs.writeFileSync(
      path.join(tmp, 'dist', 'package.json'),
      JSON.stringify({ dependencies: { 'sca-fixture-dist': '1.0.0' } })
    );
    fs.writeFileSync(
      path.join(tmp, 'package.json'),
      JSON.stringify({ dependencies: { 'sca-fixture-visible': '1.2.3' } })
    );
    const deps = parseManifestsInDir(tmp);
    check('walk skips node_modules/.git/dist', !findName(deps, 'sca-fixture-hidden') && !findName(deps, 'sca-fixture-gitdir') && !findName(deps, 'sca-fixture-dist'));
    check('walk keeps root package.json pin', findName(deps, 'sca-fixture-visible')?.version === '1.2.3');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

{
  check('invalid json returns empty', parseNpmPackageJson('not-json', 'package.json').length === 0);
  check('invalid lock json returns empty', parseNpmPackageLock('{', 'package-lock.json').length === 0);
}

{
  const pkgC = fs.readFileSync(path.join(FIXTURES, "npm-mini", "package.json"), "utf8");
  const lockC = fs.readFileSync(path.join(FIXTURES, "npm-mini", "package-lock.json"), "utf8");
  const reqC = fs.readFileSync(path.join(FIXTURES, "pypi-mini", "requirements.txt"), "utf8");
  const pipC = fs.readFileSync(path.join(FIXTURES, "pypi-mini", "Pipfile.lock"), "utf8");
  check("corrupt pkg name/version stay strings", findName(parseNpmPackageJson(pkgC, "package.json"), "!!!not-a-real-cve-pkg!!!")?.version === "9.9.9-CORRUPT");
  check("corrupt lock name/version stay strings", findName(parseNpmPackageLock(lockC, "package-lock.json"), "!!!not-a-real-cve-pkg!!!")?.version === "9.9.9-CORRUPT");
  check("corrupt req name/version stay strings", findName(parsePypiRequirements(reqC, "requirements.txt"), "!!!not-a-real-cve-wheel!!!")?.version === "0.0.1-CORRUPT");
  check("corrupt pip name/version stay strings", findName(parsePipfileLock(pipC, "Pipfile.lock"), "!!!not-a-real-cve-wheel!!!")?.version === "0.0.1-CORRUPT");
}

console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail === 0 ? 0 : 1);
