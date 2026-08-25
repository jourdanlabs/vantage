#!/usr/bin/env node
// Seal VANTAGE CODE spike receipts onto the LUNA hash-chain.
// Import the published ledger module unchanged — do not fork the chain math.
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Ledger } from "/Users/sokpyeon/projects/luna-ledger/ledger.mjs";

const sha256 = (s) => createHash("sha256").update(s).digest("hex");

const spikeDir = process.argv[2];
if (!spikeDir) {
  console.error("usage: seal.mjs <spike-dir>");
  process.exit(2);
}

const ledgerPath = path.join(spikeDir, "OPEN", "luna-ledger.jsonl");
const summaryPath = path.join(spikeDir, "OPEN", "SPIKE0-SUMMARY.json");
const summary = JSON.parse(fs.readFileSync(summaryPath, "utf8"));

const ledger = new Ledger(ledgerPath);
const genesis = ledger.append("vantage-code.spike0.open", {
  spike: "vantage-code-spike0-2026-08-23",
  finder_model: "kimi-k3",
  verifier: "pytest+verify.py (no model)",
  corpus: "QuixBugs MIT 16 python pairs + 1 same-source nonbug control",
  luna_ledger_module: "@jourdanlabs/luna-ledger",
});

for (const row of summary.cases) {
  ledger.append("vantage-code.finding", {
    case: row.case,
    location: row.location ?? null,
    claimed_wrong_behavior: row.claimed_wrong_behavior ?? null,
    repro_test_sha256: row.test_sha256,
    buggy_result: row.buggy,
    fixed_result: row.fixed,
    verdict: row.verdict,
    reason: row.reason,
  });
}

for (const ctrl of summary.controls) {
  ledger.append("vantage-code.control", ctrl);
}

const head = ledger.head;
const out = {
  genesis_sha: genesis.sha,
  head_sha: head.sha,
  n_events: ledger.events.length,
  ledger_path: ledgerPath,
  ledger_sha256: sha256(fs.readFileSync(ledgerPath)),
};
fs.writeFileSync(
  path.join(spikeDir, "OPEN", "LEDGER.sha256"),
  `${out.ledger_sha256}  luna-ledger.jsonl\n`,
);
console.log(JSON.stringify(out, null, 2));
