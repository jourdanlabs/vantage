// Minimal unified-diff generator for single-file patches.
//
// We don't need full diff semantics — templates produce line-local changes
// within one file, so we can emit a single hunk that covers a small window
// around the changed lines. This is enough for `git apply -p1` and
// `patch -p1` to accept.

export interface MakeHunkArgs {
  filePath: string;       // path that appears in the diff headers
  originalLines: string[];// full file, split by \n
  changes: Array<{
    oldStart: number;     // 1-indexed
    oldCount: number;     // number of consecutive lines to remove
    newLines: string[];   // lines to insert (no trailing \n)
  }>;
}

/**
 * Produce a unified diff string covering the given changes. Handles
 * a single file; multiple non-overlapping changes get emitted as
 * separate hunks.
 *
 * The context-line count is fixed at 3, matching `diff -u` default.
 */
export function makeUnifiedDiff(args: MakeHunkArgs): string {
  const { filePath, originalLines, changes } = args;
  if (changes.length === 0) return '';

  const CONTEXT = 3;
  const header = [
    `--- a/${filePath}`,
    `+++ b/${filePath}`,
  ].join('\n') + '\n';

  const hunks: string[] = [];

  // Build a new-file view so we can compute new line numbers per hunk
  // as we walk through changes in order.
  let lineShift = 0; // cumulative shift: newLineNumber = oldLineNumber + lineShift

  const sorted = [...changes].sort((a, b) => a.oldStart - b.oldStart);

  for (const c of sorted) {
    const oldStart = c.oldStart;
    const oldEnd = c.oldStart + c.oldCount - 1;

    const ctxStart = Math.max(1, oldStart - CONTEXT);
    const ctxEnd = Math.min(originalLines.length, oldEnd + CONTEXT);

    // Build hunk body: leading context, removals (as `-`), insertions (as `+`), trailing context
    const body: string[] = [];
    for (let i = ctxStart; i < oldStart; i++) {
      body.push(' ' + originalLines[i - 1]);
    }
    for (let i = oldStart; i <= oldEnd; i++) {
      body.push('-' + originalLines[i - 1]);
    }
    for (const nl of c.newLines) {
      body.push('+' + nl);
    }
    for (let i = oldEnd + 1; i <= ctxEnd; i++) {
      body.push(' ' + originalLines[i - 1]);
    }

    const oldRange = ctxEnd - ctxStart + 1;
    const newRange = oldRange - c.oldCount + c.newLines.length;
    const newStart = ctxStart + lineShift;

    hunks.push(
      `@@ -${ctxStart},${oldRange} +${newStart},${newRange} @@\n` +
      body.join('\n') + '\n'
    );

    lineShift += c.newLines.length - c.oldCount;
  }

  return header + hunks.join('');
}

/**
 * Detect the indentation string (leading whitespace) of a line. Used
 * when emitting new lines so they match the surrounding style.
 */
export function indentOf(line: string): string {
  const m = line.match(/^[ \t]*/);
  return m ? m[0] : '';
}
