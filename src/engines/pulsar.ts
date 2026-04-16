// PULSAR — Adversarial Stress Test Engine
// Takes high-risk files and generates adversarial findings based on code patterns

import * as path from 'path';
import { MeteorOutput, EclipseOutput, PulsarOutput, AdversarialFinding } from '../types';
import { isLanguageFullySupported } from '../languages';

function findAsyncWithoutErrorHandling(content: string, filePath: string): AdversarialFinding[] {
  const findings: AdversarialFinding[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // async function without try/catch in body
    if (/(?:async\s+function|=\s*async\s*\(|=\s*async\s+\w+\s*=>|async\s+\w+\s*\()/.test(line)) {
      // Look ahead for try/catch in next 30 lines
      const funcBody = lines.slice(i, i + 30).join('\n');
      if (!funcBody.includes('try') && !funcBody.includes('.catch(') && !funcBody.includes('Result<')) {
        // Also check it has an await
        if (funcBody.includes('await ') || funcBody.includes('.then(')) {
          const funcName = line.match(/(?:function|const|let|var)\s+(\w+)|async\s+(\w+)\s*\(/)?.slice(1).find(Boolean) || 'anonymous';
          findings.push({
            file: filePath,
            function: funcName,
            line: i + 1,
            type: 'async-race',
            severity: 'HIGH',
            description: `Async function without error boundary — unhandled rejection will crash runtime`,
            testCase: `Call ${funcName}() when network is unavailable or returns 500 — will throw unhandled promise rejection`
          });
        }
      }
    }

    // .then() without .catch()
    if (line.includes('.then(') && !line.includes('.catch(')) {
      const nextFewLines = lines.slice(i, i + 5).join('\n');
      if (!nextFewLines.includes('.catch(')) {
        findings.push({
          file: filePath,
          line: i + 1,
          type: 'error-boundary',
          severity: 'MED',
          description: `Promise chain missing .catch() — rejected promise will go unhandled`,
          testCase: `Force the promise to reject — error will be silently swallowed`
        });
      }
    }
  }

  return findings;
}

function findNullSafetyIssues(content: string, filePath: string): AdversarialFinding[] {
  const findings: AdversarialFinding[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Forced unwrap in Swift (!) — must be identifier! not boolean !
    if (/\w+!\.\w+|\w+!\s*[,)\]\s]/.test(line) && !line.trim().startsWith('//')) {
      findings.push({
        file: filePath,
        line: i + 1,
        type: 'null-safety',
        severity: 'HIGH',
        description: `Force unwrap (!) detected — will crash if value is nil`,
        testCase: `Pass nil/null for this value — will throw fatal error: unexpectedly found nil`
      });
    }

    // JS/TS accessing property without null check
    if (/\w+\.\w+\.\w+/.test(line) && !line.includes('?.') && !line.includes('||') && !line.includes('&&') && !line.trim().startsWith('//') && !line.trim().startsWith('*')) {
      // Only flag if it's in an assignment or condition (not chained method calls on clearly non-null)
      if (/(?:const|let|var)\s+\w+\s*=/.test(line) || /return\s+/.test(line)) {
        // Only flag if not using optional chaining anywhere in expression
        if (!line.includes('?.')) {
          findings.push({
            file: filePath,
            line: i + 1,
            type: 'null-safety',
            severity: 'LOW',
            description: `Deep property access without null check — may throw TypeError: Cannot read property of null`,
            testCase: `Pass undefined for any intermediate object — will throw at runtime`
          });
        }
      }
    }
  }

  return findings;
}

function findEdgeCases(content: string, filePath: string): AdversarialFinding[] {
  const findings: AdversarialFinding[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Array access without bounds check
    if (/\[\s*\d+\s*\]/.test(line) && !/\bguard\b|\bif\b/.test(lines.slice(Math.max(0, i - 2), i).join(' '))) {
      findings.push({
        file: filePath,
        line: i + 1,
        type: 'edge-case',
        severity: 'LOW',
        description: `Direct array index access — will crash on empty array`,
        testCase: `Pass empty array — index out of bounds`
      });
    }

    // Division without zero check
    if (/\/\s*\w+(?!\s*[=!<>])/.test(line) && !/\/\//g.test(line.trim().slice(0, 2))) {
      if (!/typeof|length|\.length/.test(line)) {
        // Don't flag comments or string divisions, only actual math
        if (/[\d\w]\s*\/\s*[\w]/.test(line) && !line.trim().startsWith('//') && !line.trim().startsWith('*')) {
          findings.push({
            file: filePath,
            line: i + 1,
            type: 'edge-case',
            severity: 'LOW',
            description: `Division operation — potential division by zero not guarded`,
            testCase: `Pass zero as divisor — NaN or Infinity result`
          });
        }
      }
    }
  }

  return findings;
}

function findMissingErrorBoundaries(content: string, filePath: string, language: string): AdversarialFinding[] {
  const findings: AdversarialFinding[] = [];
  const lines = content.split('\n');

  if (language === 'typescript' || language === 'javascript') {
    // JSON.parse without try/catch
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes('JSON.parse(') && !lines[i].includes('try')) {
        const context = lines.slice(Math.max(0, i - 3), i + 3).join('\n');
        if (!context.includes('try')) {
          findings.push({
            file: filePath,
            line: i + 1,
            type: 'error-boundary',
            severity: 'MED',
            description: `JSON.parse() without try/catch — malformed JSON will throw SyntaxError`,
            testCase: `Pass malformed JSON string like '{bad json' — will throw SyntaxError at runtime`
          });
        }
      }
    }
  }

  if (language === 'swift') {
    // throws functions called without try
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/\w+\(.*\)/.test(line) && !line.includes('try') && !line.includes('//') && lines[i - 1]?.includes('throws')) {
        findings.push({
          file: filePath,
          line: i + 1,
          type: 'error-boundary',
          severity: 'MED',
          description: `Swift throwing function called without try — error will propagate unhandled`,
          testCase: `Force error condition in callee — crash without proper error propagation`
        });
      }
    }
  }

  return findings;
}

// ── Injection vulnerability patterns ─────────────────────────────────────────

function findInjectionVulnerabilities(content: string, filePath: string): AdversarialFinding[] {
  const findings: AdversarialFinding[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

    // eval() on user-controlled input: eval(req., eval(process.argv., eval(params., eval(query., eval(body.
    if (/\beval\s*\(/.test(line)) {
      const evalArg = line.match(/\beval\s*\(\s*(.{0,80})/)?.[1] ?? '';
      const isUserControlled = /req\.|process\.argv|params\.|query\.|body\.|input|user|payload|data/i.test(evalArg);
      const severity = isUserControlled ? 'HIGH' : 'MED';
      findings.push({
        file: filePath,
        line: i + 1,
        type: 'injection',
        severity,
        description: isUserControlled
          ? `eval() on user-controlled input — arbitrary code execution`
          : `eval() detected — verify input is not user-controlled`,
        testCase: `Pass \`process.exit(1)\` or \`require('child_process').execSync('...')\` as input — arbitrary code execution`,
      });
    }

    // NoSQL $where injection: $where with template literal or string concat
    if (line.includes('$where')) {
      const hasTemplateLiteral = line.includes('$where') && line.includes('`') && /\$\{/.test(line);
      const hasStringConcat = line.includes('$where') && /['"]\s*\+/.test(line);
      if (hasTemplateLiteral || hasStringConcat) {
        findings.push({
          file: filePath,
          line: i + 1,
          type: 'injection',
          severity: 'HIGH',
          description: `NoSQL $where injection — user-controlled JS expression passed to MongoDB $where`,
          testCase: `Set field to \`'; sleep(5000); //\` — causes server-side JS execution in MongoDB`,
        });
      }
    }

    // ReDoS: new RegExp() with user-controlled input
    if (/new\s+RegExp\s*\(/.test(line)) {
      const regexpArg = line.match(/new\s+RegExp\s*\(\s*(.{0,80})/)?.[1] ?? '';
      const argTrimmed = regexpArg.trim();
      // Flag if: (a) argument is a bare variable/expression, or
      //          (b) argument is a template literal containing interpolation `...${...}`
      const isPlainLiteral = /^['"]/.test(argTrimmed);
      const isInterpolatedTemplate = argTrimmed.startsWith('`') && argTrimmed.includes('${');
      if (!isPlainLiteral || isInterpolatedTemplate) {
        findings.push({
          file: filePath,
          line: i + 1,
          type: 'injection',
          severity: 'MED',
          description: `new RegExp() with non-literal argument — potential ReDoS if input is user-controlled`,
          testCase: `Pass catastrophic backtracking pattern like \`(a+)+$\` — regex engine hangs`,
        });
      }
    }
  }

  return findings;
}

// ── Hardcoded secret patterns ─────────────────────────────────────────────────

function findHardcodedSecrets(content: string, filePath: string): AdversarialFinding[] {
  const findings: AdversarialFinding[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

    // PEM private key block
    if (line.includes('-----BEGIN') && /PRIVATE KEY|RSA PRIVATE|EC PRIVATE|DSA PRIVATE/.test(line)) {
      findings.push({
        file: filePath,
        line: i + 1,
        type: 'hardcoded-secret',
        severity: 'HIGH',
        description: `PEM private key hardcoded in source — key material exposed in version control`,
        testCase: `Check git log — key is permanently in history even if later removed`,
      });
    }

    // AWS access key: AKIA prefix (20-char uppercase)
    if (/AKIA[0-9A-Z]{16}/.test(line)) {
      findings.push({
        file: filePath,
        line: i + 1,
        type: 'hardcoded-secret',
        severity: 'HIGH',
        description: `AWS access key ID detected (AKIA prefix) — credential exposure`,
        testCase: `Run \`aws sts get-caller-identity\` with this key — if valid, full AWS account access`,
      });
    }

    // Stripe live secret key: sk_live_
    if (/sk_live_[a-zA-Z0-9]{20,}/.test(line)) {
      findings.push({
        file: filePath,
        line: i + 1,
        type: 'hardcoded-secret',
        severity: 'HIGH',
        description: `Stripe live secret key hardcoded (sk_live_ prefix) — billing account exposure`,
        testCase: `Use key against Stripe API — full read/write access to payment data`,
      });
    }

    // Generic: variable/constant whose name contains a sensitive keyword, assigned a literal string ≥20 chars.
    // Require a declaration or assignment context (const/let/var/export, or identifier on lhs of = not inside a string).
    // The negative lookbehind [^'"`\w] prevents matching SQL field names like `password = '...'` inside a template.
    const secretAssign = line.match(/(?:^|[\s,(])(?:const|let|var|export\s+const)\s+\w*(?:secret|apikey|api_key|token|password|passwd|credential|hmac|signing)\w*\s*[=:]\s*['"`]([^'"`]{20,})['"`]/i)
      ?? line.match(/\b(?:secret|apikey|api_key|hmac_?secret|signing_?secret|jwt_?secret|session_?secret)\s*[:=]\s*['"`]([^'"`]{20,})['"`]/i);
    if (secretAssign) {
      const value = secretAssign[1];
      // Skip obvious placeholders and test values
      if (!/placeholder|changeme|your_key|example|XXXXXX|insert_|test_|<YOUR|TODO|FIXME/i.test(value)) {
        findings.push({
          file: filePath,
          line: i + 1,
          type: 'hardcoded-secret',
          severity: 'HIGH',
          description: `Hardcoded secret/key/token value — sensitive credential in source`,
          testCase: `Confirm the value is a real credential — if so, rotate immediately`,
        });
      }
    }

    // Hex string ≥32 chars assigned to identifier with sensitive name (same declaration-context requirement)
    const hexAssign = line.match(/(?:^|[\s,(])(?:const|let|var|export\s+const)\s+\w*(?:secret|key|token|hash|salt|hmac|seed)\w*\s*=\s*['"`]([0-9a-fA-F]{32,})['"`]/i);
    if (hexAssign && !secretAssign) {
      findings.push({
        file: filePath,
        line: i + 1,
        type: 'hardcoded-secret',
        severity: 'HIGH',
        description: `Hardcoded hex key/token (${hexAssign[1].length} chars) — cryptographic material in source`,
        testCase: `Confirm this is a real key, not a test fixture — if real, rotate and remove from source`,
      });
    }

    // Crypto function call with hardcoded literal key: createHmac, createCipher, createSign, etc.
    const cryptoCall = line.match(/\.create(?:Hmac|Cipher|CipherIv|Sign|Verify)\s*\([^)]*,\s*['"`]([^'"`]{8,})['"`]/);
    if (cryptoCall) {
      const value = cryptoCall[1];
      if (!/placeholder|changeme|example|XXXXXX|test_/i.test(value)) {
        findings.push({
          file: filePath,
          line: i + 1,
          type: 'hardcoded-secret',
          severity: 'HIGH',
          description: `Hardcoded key in crypto function call — secret embedded directly in code`,
          testCase: `Confirm the value is a real key — extract to environment variable`,
        });
      }
    }
  }

  return findings;
}

export async function runPULSAR(
  meteor: MeteorOutput,
  eclipse: EclipseOutput,
  onProgress?: (msg: string) => void
): Promise<PulsarOutput> {
  onProgress?.('scanning all files for adversarial patterns');

  const allFindings: AdversarialFinding[] = [];
  const missingGuards: string[] = [];
  const recommendations: string[] = [];

  // PULSAR runs on every scanned file — ECLIPSE gating removed.
  // ECLIPSE tier is still available to AURORA for weighted scoring (high-risk
  // files with PULSAR findings penalize more heavily there).
  let processedCount = 0;
  for (const file of meteor.files) {
    if (file.language === 'markdown') continue;

    // Skip files whose language doesn't have reliable extraction — PULSAR
    // patterns are JS/TS/Swift-centric and produce noise on other syntaxes.
    const ext = path.extname(file.path).toLowerCase();
    if (!isLanguageFullySupported(ext)) continue;

    const { content, path: filePath, language } = file;

    const asyncFindings = findAsyncWithoutErrorHandling(content, filePath);
    const nullFindings = findNullSafetyIssues(content, filePath);
    const edgeFindings = findEdgeCases(content, filePath);
    const boundaryFindings = findMissingErrorBoundaries(content, filePath, language);
    const injectionFindings = findInjectionVulnerabilities(content, filePath);
    const secretFindings = findHardcodedSecrets(content, filePath);

    allFindings.push(...asyncFindings, ...nullFindings, ...edgeFindings, ...boundaryFindings, ...injectionFindings, ...secretFindings);
    processedCount++;
  }

  // Deduplicate similar findings (same file + same type within 3 lines)
  const deduped: AdversarialFinding[] = [];
  const seen = new Set<string>();
  for (const finding of allFindings) {
    const key = `${finding.file}:${finding.type}:${Math.floor((finding.line || 0) / 3)}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(finding);
    }
  }

  // Generate missing guards summary
  const asyncCount = deduped.filter(f => f.type === 'async-race').length;
  const nullCount = deduped.filter(f => f.type === 'null-safety').length;
  const boundaryCount = deduped.filter(f => f.type === 'error-boundary').length;
  const injectionCount = deduped.filter(f => f.type === 'injection').length;
  const secretCount = deduped.filter(f => f.type === 'hardcoded-secret').length;

  if (asyncCount > 0) missingGuards.push(`${asyncCount} async functions missing error handling`);
  if (nullCount > 0) missingGuards.push(`${nullCount} potential null/undefined dereferences`);
  if (boundaryCount > 0) missingGuards.push(`${boundaryCount} missing error boundaries`);
  if (injectionCount > 0) missingGuards.push(`${injectionCount} injection vulnerabilities (eval/NoSQL/$where/ReDoS)`);
  if (secretCount > 0) missingGuards.push(`${secretCount} hardcoded secrets/credentials`);

  // Build recommendations from findings
  if (secretCount > 0) {
    recommendations.push(`CRITICAL: ${secretCount} hardcoded secret(s) found — rotate credentials and remove from source immediately`);
  }

  const evalFindings = deduped.filter(f => f.type === 'injection' && f.description.includes('eval()') && f.severity === 'HIGH');
  if (evalFindings.length > 0) {
    recommendations.push(`CRITICAL: ${evalFindings.length} eval() call(s) on user input — arbitrary code execution vector, remove eval() entirely`);
  }

  const nosqlFindings = deduped.filter(f => f.type === 'injection' && f.description.includes('$where'));
  if (nosqlFindings.length > 0) {
    recommendations.push(`CRITICAL: ${nosqlFindings.length} NoSQL $where injection(s) — replace with safe operators ($eq, $gt) and parameterized queries`);
  }

  const redosFindings = deduped.filter(f => f.type === 'injection' && f.description.includes('ReDoS'));
  if (redosFindings.length > 0) {
    recommendations.push(`${redosFindings.length} potential ReDoS via new RegExp() — validate pattern is not user-supplied`);
  }

  if (asyncCount > 0) {
    recommendations.push(`Wrap ${asyncCount} async functions in try/catch or .catch() before shipping`);
  }

  const forceUnwraps = deduped.filter(f => f.type === 'null-safety' && f.description.includes('Force unwrap'));
  if (forceUnwraps.length > 0) {
    recommendations.push(`Replace ${forceUnwraps.length} force unwraps (!) with optional chaining (?.) or guard statements`);
  }

  if (deduped.filter(f => f.type === 'error-boundary' && f.description.includes('JSON.parse')).length > 0) {
    recommendations.push(`Wrap all JSON.parse() calls in try/catch — malformed API responses will crash the app`);
  }

  onProgress?.(`${deduped.length} findings across ${processedCount} files`);

  return {
    adversarialFindings: deduped,
    missingGuards,
    recommendations
  };
}
