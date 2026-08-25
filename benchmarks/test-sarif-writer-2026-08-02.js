#!/usr/bin/env node
// Unit checks for SARIF writer — URI form + 1-based lines. Exit 0 only if all pass.
const path = require('path');
const fs = require('fs');
const assert = require('assert');
const {
  toScanRelativeUri,
  toSarifStartLine,
  findingsToSarif,
  reportToSarif,
} = require(path.join(__dirname, '..', 'dist', 'sarif.js'));

const root = '/tmp/vantage-sarif-unit';
fs.mkdirSync(path.join(root, 'sub'), { recursive: true });

// --- URI ---
assert.strictEqual(toScanRelativeUri(root, path.join(root, 'a.js')), 'a.js');
assert.strictEqual(toScanRelativeUri(root, path.join(root, 'sub', 'b.js')), 'sub/b.js');
assert.strictEqual(toScanRelativeUri(root, 'a.js'), 'a.js'); // already relative
assert.ok(!toScanRelativeUri(root, path.join(root, 'a.js')).startsWith('file://'));
assert.ok(!path.isAbsolute(toScanRelativeUri(root, path.join(root, 'a.js'))));
// outside root → basename fallback
assert.strictEqual(toScanRelativeUri(root, '/other/benchmark_test_00042.js'), 'benchmark_test_00042.js');

// --- line base ---
assert.strictEqual(toSarifStartLine(1), 1);
assert.strictEqual(toSarifStartLine(42), 42);
assert.strictEqual(toSarifStartLine(0), 1); // promote
assert.strictEqual(toSarifStartLine(-3), 1);
assert.strictEqual(toSarifStartLine(undefined), 1);
assert.strictEqual(toSarifStartLine(3.9), 3);

// --- full log shape ---
const findings = [
  {
    file: path.join(root, 'benchmark_test_00001.js'),
    line: 7,
    type: 'injection',
    severity: 'HIGH',
    description: 'eval of user input',
    testCase: 'x',
  },
  {
    file: path.join(root, 'sub', 'benchmark_test_00002.js'),
    line: 1,
    type: 'hardcoded-secret',
    severity: 'MED',
    description: 'secret',
    testCase: 'y',
  },
];
const sarif = findingsToSarif(findings, { scanRoot: root, toolVersion: '1.0.0-test' });
assert.strictEqual(sarif.version, '2.1.0');
assert.strictEqual(sarif.runs.length, 1);
assert.strictEqual(sarif.runs[0].results.length, 2);
assert.strictEqual(sarif.runs[0].results[0].ruleId, 'injection');
assert.strictEqual(
  sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,
  'benchmark_test_00001.js'
);
assert.strictEqual(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 7);
assert.strictEqual(
  sarif.runs[0].results[1].locations[0].physicalLocation.artifactLocation.uri,
  'sub/benchmark_test_00002.js'
);
// CWE tags present on injection rule
const injRule = sarif.runs[0].tool.driver.rules.find((r) => r.id === 'injection');
assert.ok(injRule.properties.tags.some((t) => /cwe/i.test(t)));

// reportToSarif N→N
const report = {
  target: root,
  timestamp: new Date().toISOString(),
  pulsar: { adversarialFindings: findings, missingGuards: [], recommendations: [] },
  meteor: {},
  nova: {},
  eclipse: {},
  aurora: {},
};
const sarif2 = reportToSarif(report, { scanRoot: root });
assert.strictEqual(sarif2.runs[0].results.length, findings.length);

console.log('PASS test-sarif-writer-2026-08-02.js');
