#!/usr/bin/env node
// Posts VANTAGE verdict as a PR comment via GitHub API

const fs = require('fs');
const https = require('https');

const reportPath = process.env.REPORT_PATH;
const verdict = process.env.VERDICT;
const score = process.env.SCORE;
const token = process.env.GH_TOKEN;

const [owner, repo] = (process.env.GITHUB_REPOSITORY || '').split('/');
const prNumber = process.env.GITHUB_REF?.match(/refs\/pull\/(\d+)\/merge/)?.[1];

if (!prNumber) {
  console.log('Not a PR context — skipping comment.');
  process.exit(0);
}

let report = null;
if (reportPath && fs.existsSync(reportPath)) {
  try {
    report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  } catch {
    // ignore
  }
}

function formatBody() {
  const icon = verdict === 'APPROVED' ? '✅' : '❌';
  const aurora = report?.aurora ?? {};
  const breakdown = aurora.breakdown ?? {};
  const metrics = report?.meteor?.metrics ?? {};
  const topIssues = (aurora.topIssues ?? []).slice(0, 5);

  const topIssuesRows = topIssues.length > 0
    ? topIssues.map(i => {
        const sev = i.severity === 'HIGH' ? '🔴' : i.severity === 'MED' ? '🟡' : '🟢';
        const file = (i.file || '').split('/').pop() + (i.line ? `:${i.line}` : '');
        return `| ${sev} ${i.severity} | \`${file}\` | ${i.description} |`;
      }).join('\n')
    : '| — | — | No issues found |';

  return `## ${icon} VANTAGE — ${verdict} (${score})

<details>
<summary>Score breakdown</summary>

| Dimension | Score |
|---|---|
| Complexity | ${((breakdown.complexityScore ?? 0) * 100).toFixed(0)}% |
| Dependency | ${((breakdown.dependencyScore ?? 0) * 100).toFixed(0)}% |
| Risk Score | ${((breakdown.riskScore ?? 0) * 100).toFixed(0)}% |
| Adversarial | ${((breakdown.adversarialScore ?? 0) * 100).toFixed(0)}% |

**${report?.meteor?.files?.length ?? 0} files · ${(metrics.linesOfCode ?? 0).toLocaleString()} LOC · ${report?.pulsar?.adversarialFindings?.length ?? 0} findings**

</details>

### Top Issues

| Severity | File | Description |
|---|---|---|
${topIssuesRows}

${aurora.summary ?? ''}

---
*Powered by [VANTAGE](https://github.com/jourdanlabs/vantage) — Autonomous Code Evolution Engine*`;
}

function postComment(body) {
  const data = JSON.stringify({ body });
  const options = {
    hostname: 'api.github.com',
    path: `/repos/${owner}/${repo}/issues/${prNumber}/comments`,
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data),
      'User-Agent': 'vantage-action/1.0',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  };

  return new Promise((resolve, reject) => {
    const req = https.request(options, res => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(body);
        } else {
          reject(new Error(`GitHub API error ${res.statusCode}: ${body}`));
        }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

postComment(formatBody())
  .then(() => console.log('PR comment posted.'))
  .catch(err => {
    console.error('Failed to post PR comment:', err.message);
    // Don't fail the workflow for comment errors
    process.exit(0);
  });
