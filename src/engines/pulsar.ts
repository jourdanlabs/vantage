// PULSAR — Adversarial Stress Test Engine
// Takes high-risk files and generates adversarial findings based on code patterns

import * as path from 'path';
import { MeteorOutput, EclipseOutput, PulsarOutput, AdversarialFinding } from '../types';

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

export async function runPULSAR(
  meteor: MeteorOutput,
  eclipse: EclipseOutput,
  onProgress?: (msg: string) => void
): Promise<PulsarOutput> {
  onProgress?.('stress-testing high-risk files');

  const allFindings: AdversarialFinding[] = [];
  const missingGuards: string[] = [];
  const recommendations: string[] = [];

  // Only stress-test high-risk files (plus medium to get coverage)
  const targetFiles = new Set([
    ...eclipse.highRisk.map(r => r.file),
    ...eclipse.medRisk.map(r => r.file)
  ]);

  let processedCount = 0;
  for (const file of meteor.files) {
    if (!targetFiles.has(file.path)) continue;
    if (file.language === 'markdown') continue;

    const { content, path: filePath, language } = file;

    const asyncFindings = findAsyncWithoutErrorHandling(content, filePath);
    const nullFindings = findNullSafetyIssues(content, filePath);
    const edgeFindings = findEdgeCases(content, filePath);
    const boundaryFindings = findMissingErrorBoundaries(content, filePath, language);

    allFindings.push(...asyncFindings, ...nullFindings, ...edgeFindings, ...boundaryFindings);
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

  if (asyncCount > 0) missingGuards.push(`${asyncCount} async functions missing error handling`);
  if (nullCount > 0) missingGuards.push(`${nullCount} potential null/undefined dereferences`);
  if (boundaryCount > 0) missingGuards.push(`${boundaryCount} missing error boundaries`);

  // Build recommendations from findings
  const highSeverity = deduped.filter(f => f.severity === 'HIGH');
  if (highSeverity.length > 0) {
    recommendations.push(`CRITICAL: Wrap ${asyncCount} async functions in try/catch before shipping`);
    recommendations.push(`Add error boundaries to all API calls and network operations`);
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
