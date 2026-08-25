// HCL / Terraform config-tree parser (v1)
// Resource blocks, labels, attributes. No module expansion. No variable tracing.
// No HashiCorp libraries — subset scanner sufficient for structural rules.
//
// Bounded: every loop must advance the cursor or trip a step/time budget.
// Function calls, interpolations, and for-expressions are consumed — never hung.

export type HclScalar = string | number | boolean | null;

export interface HclValue {
  kind: 'string' | 'number' | 'bool' | 'null' | 'ident' | 'list' | 'object';
  raw: unknown;
  startLine: number;
}

export interface HclAttribute {
  name: string;
  value: HclValue;
  startLine: number;
}

export interface HclBlock {
  blockType: string;
  labels: string[];
  attributes: HclAttribute[];
  blocks: HclBlock[];
  startLine: number;
  endLine: number;
}

export interface HclDocument {
  file: string;
  blocks: HclBlock[];
  notes: string[];
}

export interface ParseHclOptions {
  /** Wall-clock budget. Default 8000ms. Checked synchronously (tight loops never yield). */
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 8000;
const MAX_DEPTH = 256;

function isIdentStart(ch: string): boolean {
  const c = ch.charCodeAt(0);
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
}

function isIdentCont(ch: string): boolean {
  const c = ch.charCodeAt(0);
  return isIdentStart(ch) || (c >= 48 && c <= 57) || c === 45;
}

function isValueIdentChar(ch: string): boolean {
  const c = ch.charCodeAt(0);
  // A-Za-z0-9 _ - . / $
  return isIdentCont(ch) || c === 46 || c === 47 || c === 36;
}

function isDigit(ch: string): boolean {
  const c = ch.charCodeAt(0);
  return c >= 48 && c <= 57;
}

class Scan {
  src: string;
  i = 0;
  line = 1;
  steps = 0;
  maxSteps: number;
  deadline: number;
  timedOut = false;
  depth = 0;
  notes: string[] = [];
  file: string;

  constructor(src: string, file: string, timeoutMs: number) {
    this.src = src;
    this.file = file;
    this.maxSteps = Math.max(1_000_000, src.length * 64);
    this.deadline = Date.now() + Math.max(50, timeoutMs);
  }

  guard(): boolean {
    if (this.timedOut) return false;
    this.steps++;
    if (this.steps > this.maxSteps) {
      this.timedOut = true;
      this.notes.push(`${this.file}:${this.line}: parse error — step budget exceeded`);
      return false;
    }
    if ((this.steps & 4095) === 0 && Date.now() > this.deadline) {
      this.timedOut = true;
      this.notes.push(`${this.file}:${this.line}: parse error — time budget exceeded`);
      return false;
    }
    return true;
  }

  eof(): boolean {
    return this.timedOut || this.i >= this.src.length;
  }

  peek(n = 0): string {
    return this.src[this.i + n] ?? '';
  }

  advance(): string {
    if (this.i >= this.src.length) return '';
    const ch = this.src[this.i++];
    if (ch === '\n') this.line++;
    return ch;
  }

  /** Must move the cursor forward by at least one source character. */
  forceAdvance(): void {
    if (this.i < this.src.length) this.advance();
    else this.timedOut = true;
  }

  skipTrivia(): void {
    while (this.guard() && !this.eof()) {
      const ch = this.peek();
      if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
        this.advance();
        continue;
      }
      if (ch === '#') {
        while (this.guard() && !this.eof() && this.peek() !== '\n') this.advance();
        continue;
      }
      if (ch === '/' && this.peek(1) === '/') {
        this.advance();
        this.advance();
        while (this.guard() && !this.eof() && this.peek() !== '\n') this.advance();
        continue;
      }
      if (ch === '/' && this.peek(1) === '*') {
        this.advance();
        this.advance();
        while (this.guard() && !this.eof() && !(this.peek() === '*' && this.peek(1) === '/')) {
          this.advance();
        }
        if (!this.eof()) {
          this.advance();
          this.advance();
        }
        continue;
      }
      break;
    }
  }

  enter(): boolean {
    this.depth++;
    if (this.depth > MAX_DEPTH) {
      this.notes.push(`${this.file}:${this.line}: parse error — max nest depth`);
      return false;
    }
    return true;
  }

  leave(): void {
    if (this.depth > 0) this.depth--;
  }
}

function readIdent(s: Scan): string {
  let out = '';
  if (isIdentStart(s.peek()) || s.peek() === '-') {
    out += s.advance();
    while (isIdentCont(s.peek())) out += s.advance();
  }
  return out;
}

function readString(s: Scan): string {
  const quote = s.advance(); // " or '
  let out = '';
  while (s.guard() && !s.eof() && s.peek() !== quote) {
    if (s.peek() === '\\') {
      s.advance();
      const esc = s.advance();
      const map: Record<string, string> = { n: '\n', t: '\t', r: '\r', '"': '"', "'": "'", '\\': '\\' };
      out += map[esc] ?? esc;
      continue;
    }
    // Interpolation / template: ${ ... } or %{ ... } may contain nested quotes.
    if ((s.peek() === '$' || s.peek() === '%') && s.peek(1) === '{') {
      out += s.advance();
      out += s.advance();
      out += readInterpolationBody(s);
      continue;
    }
    out += s.advance();
  }
  if (s.peek() === quote) s.advance();
  return out;
}

/** Consume until the matching `}` of an interpolation, tracking nest + nested strings. */
function readInterpolationBody(s: Scan): string {
  let out = '';
  let depth = 1;
  while (s.guard() && !s.eof() && depth > 0) {
    const ch = s.peek();
    if (ch === '"' || ch === "'") {
      out += ch;
      out += readString(s);
      out += ch;
      continue;
    }
    if (ch === '{') {
      depth++;
      out += s.advance();
      continue;
    }
    if (ch === '}') {
      depth--;
      out += s.advance();
      continue;
    }
    if (ch === '\\') {
      out += s.advance();
      if (!s.eof()) out += s.advance();
      continue;
    }
    out += s.advance();
  }
  return out;
}

function readNumber(s: Scan): number {
  let out = '';
  if (s.peek() === '-') out += s.advance();
  while (isDigit(s.peek())) out += s.advance();
  if (s.peek() === '.') {
    out += s.advance();
    while (isDigit(s.peek())) out += s.advance();
  }
  return Number(out);
}

function readHeredoc(s: Scan): string {
  // <<EOF or <<-EOF
  s.advance(); // <
  s.advance(); // <
  if (s.peek() === '-') s.advance();
  let marker = '';
  while (isIdentCont(s.peek())) marker += s.advance();
  while (s.guard() && !s.eof() && s.peek() !== '\n') s.advance();
  if (s.peek() === '\n') s.advance();
  const lines: string[] = [];
  while (s.guard() && !s.eof()) {
    let line = '';
    while (s.guard() && !s.eof() && s.peek() !== '\n') line += s.advance();
    if (s.peek() === '\n') s.advance();
    if (line.trim() === marker) break;
    lines.push(line);
  }
  return lines.join('\n');
}

function startsForKeyword(s: Scan): boolean {
  if (s.peek() !== 'f' || s.peek(1) !== 'o' || s.peek(2) !== 'r') return false;
  const next = s.peek(3);
  return next === '' || next === ' ' || next === '\t' || next === '\n' || next === '\r' || next === '#';
}

function parseCallArgs(s: Scan): HclValue[] {
  // current is '('
  s.advance();
  const args: HclValue[] = [];
  while (s.guard() && !s.eof()) {
    const loopAt = s.i;
    s.skipTrivia();
    if (s.peek() === ')') {
      s.advance();
      break;
    }
    if (s.peek() === ',') {
      s.advance();
      continue;
    }
    args.push(parseValue(s));
    if (s.i === loopAt) s.forceAdvance();
  }
  return args;
}

function parseValue(s: Scan): HclValue {
  s.skipTrivia();
  const startLine = s.line;
  if (!s.enter()) {
    if (!s.eof()) s.forceAdvance();
    s.leave();
    return { kind: 'ident', raw: '', startLine };
  }
  try {
    const primary = parsePrimary(s);
    consumeExpressionTail(s);
    return primary;
  } finally {
    s.leave();
  }
}

function parsePrimary(s: Scan): HclValue {
  s.skipTrivia();
  const startLine = s.line;
  const ch = s.peek();
  if (ch === '"' || ch === "'") {
    return { kind: 'string', raw: readString(s), startLine };
  }
  if (ch === '<' && s.peek(1) === '<') {
    return { kind: 'string', raw: readHeredoc(s), startLine };
  }
  if (ch === '[') {
    return parseList(s);
  }
  if (ch === '{') {
    return { kind: 'object', raw: parseObjectBody(s), startLine };
  }
  if (ch === '-' && isDigit(s.peek(1))) {
    return { kind: 'number', raw: readNumber(s), startLine };
  }
  if (isDigit(ch)) {
    return { kind: 'number', raw: readNumber(s), startLine };
  }
  // ident / bool / null / dotted ref / function call
  if (isIdentStart(ch) || ch === '$') {
    let ident = '';
    while (!s.eof() && isValueIdentChar(s.peek())) ident += s.advance();
    if (ident === 'true') return { kind: 'bool', raw: true, startLine };
    if (ident === 'false') return { kind: 'bool', raw: false, startLine };
    if (ident === 'null') return { kind: 'null', raw: null, startLine };
    s.skipTrivia();
    if (s.peek() === '(') {
      const args = parseCallArgs(s);
      // Unwrap jsonencode(...) so IAM policy objects stay visible as attributes.
      if (ident === 'jsonencode' && args.length === 1) return args[0];
      return { kind: 'ident', raw: ident, startLine };
    }
    return { kind: 'ident', raw: ident, startLine };
  }
  // Unknown punctuation ( ':', ')', '?', '(', '=', '>', ... ). MUST consume.
  if (!s.eof()) {
    const raw = s.advance();
    return { kind: 'ident', raw, startLine };
  }
  return { kind: 'ident', raw: '', startLine };
}

function consumeExpressionTail(s: Scan): void {
  // Consume operators / postfix so leftovers cannot stall the parent loop.
  while (s.guard() && !s.eof()) {
    s.skipTrivia();
    const ch = s.peek();
    if (ch === '.') {
      s.advance();
      if (s.peek() === '*') s.advance();
      else if (isIdentStart(s.peek())) readIdent(s);
      else if (s.peek() === '[') parseList(s);
      continue;
    }
    if (ch === '[') {
      parseList(s);
      continue;
    }
    if (ch === '(') {
      parseCallArgs(s);
      continue;
    }
    // comparison / logical / arithmetic / ternary / fat-arrow
    if (ch === '=' && s.peek(1) !== '=' && s.peek(1) !== '>') break;
    if ('+-*/%<>=!&|?:'.includes(ch)) {
      s.advance();
      if ((ch === '=' || ch === '!' || ch === '<' || ch === '>' || ch === '&' || ch === '|') && s.peek() === (ch === '!' ? '=' : ch)) {
        s.advance();
      }
      if (ch === '=' && s.peek() === '>') s.advance();
      parsePrimary(s);
      continue;
    }
    break;
  }
}

function parseList(s: Scan): HclValue {
  const startLine = s.line;
  s.advance(); // [
  s.skipTrivia();
  if (startsForKeyword(s)) {
    skipBalanced(s, '[', ']');
    return { kind: 'list', raw: [], startLine };
  }
  const items: HclValue[] = [];
  while (s.guard() && !s.eof()) {
    const loopAt = s.i;
    s.skipTrivia();
    if (s.peek() === ']') {
      s.advance();
      break;
    }
    if (s.peek() === ',') {
      s.advance();
      continue;
    }
    items.push(parseValue(s));
    if (s.i === loopAt) s.forceAdvance();
  }
  return { kind: 'list', raw: items, startLine };
}

function parseObjectBody(s: Scan): Record<string, HclValue> {
  if (s.peek() === '{') s.advance();
  s.skipTrivia();
  if (startsForKeyword(s)) {
    skipBalanced(s, '{', '}');
    return {};
  }
  const out: Record<string, HclValue> = {};
  while (s.guard() && !s.eof()) {
    const loopAt = s.i;
    s.skipTrivia();
    if (s.peek() === '}') {
      s.advance();
      break;
    }
    if (s.peek() === ',') {
      s.advance();
      continue;
    }
    let key = '';
    if (s.peek() === '"' || s.peek() === "'") key = readString(s);
    else key = readIdent(s);
    s.skipTrivia();
    if (s.peek() === '=' && s.peek(1) === '>') {
      s.advance();
      s.advance();
    } else if (s.peek() === '=') s.advance();
    else if (s.peek() === ':') s.advance();
    if (key) out[key] = parseValue(s);
    else parseValue(s);
    s.skipTrivia();
    if (s.peek() === ',') s.advance();
    if (s.i === loopAt) s.forceAdvance();
  }
  return out;
}

/** Already consumed `open`. Skip to matching `close`, respecting strings. */
function skipBalanced(s: Scan, open: string, close: string): void {
  // Caller has already consumed `open` for lists/objects; we start at depth 1.
  let depth = 1;
  while (s.guard() && !s.eof() && depth > 0) {
    const ch = s.peek();
    if (ch === '"' || ch === "'") {
      readString(s);
      continue;
    }
    if (ch === '#' || (ch === '/' && (s.peek(1) === '/' || s.peek(1) === '*'))) {
      s.skipTrivia();
      continue;
    }
    if (ch === open) {
      depth++;
      s.advance();
      continue;
    }
    if (ch === close) {
      depth--;
      s.advance();
      continue;
    }
    s.advance();
  }
}

function parseBlock(s: Scan): HclBlock {
  s.skipTrivia();
  const startLine = s.line;
  if (!s.enter()) {
    if (!s.eof()) s.forceAdvance();
    s.leave();
    return { blockType: '', labels: [], attributes: [], blocks: [], startLine, endLine: s.line };
  }
  try {
    const blockType = readIdent(s);
    const labels: string[] = [];
    s.skipTrivia();
    while (s.guard() && !s.eof()) {
      const loopAt = s.i;
      s.skipTrivia();
      if (s.peek() === '"' || s.peek() === "'") {
        labels.push(readString(s));
        continue;
      }
      if (isIdentStart(s.peek()) && s.peek() !== '{') {
        const maybe = readIdent(s);
        s.skipTrivia();
        if (s.peek() === '{' || s.peek() === '"' || isIdentStart(s.peek())) {
          labels.push(maybe);
          continue;
        }
      }
      if (s.i === loopAt) break;
      break;
    }
    s.skipTrivia();
    if (s.peek() !== '{') {
      return { blockType, labels, attributes: [], blocks: [], startLine, endLine: s.line };
    }
    s.advance(); // {
    const attributes: HclAttribute[] = [];
    const blocks: HclBlock[] = [];
    while (s.guard() && !s.eof()) {
      const loopAt = s.i;
      s.skipTrivia();
      if (s.peek() === '}') {
        s.advance();
        break;
      }
      const itemStart = s.i;
      const itemLine = s.line;
      let name = '';
      if (s.peek() === '"' || s.peek() === "'") name = readString(s);
      else name = readIdent(s);
      s.skipTrivia();
      if (s.peek() === '=') {
        s.advance();
        const value = parseValue(s);
        attributes.push({ name, value, startLine: itemLine });
        if (s.i === loopAt) s.forceAdvance();
        continue;
      }
      // nested block: name [labels] {
      s.i = itemStart;
      s.line = itemLine;
      if (name && (s.peek() === '"' || isIdentStart(s.peek()))) {
        blocks.push(parseBlock(s));
      } else {
        // leftover punctuation (function-call '(' used to hang here)
        s.forceAdvance();
      }
      if (s.i === loopAt) s.forceAdvance();
    }
    return { blockType, labels, attributes, blocks, startLine, endLine: s.line };
  } finally {
    s.leave();
  }
}

export function parseHcl(content: string, file = '', opts?: ParseHclOptions): HclDocument {
  const timeoutMs = opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const s = new Scan(content, file, timeoutMs);
  const blocks: HclBlock[] = [];
  while (s.guard() && !s.eof()) {
    const loopAt = s.i;
    s.skipTrivia();
    if (s.eof()) break;
    try {
      if (!isIdentStart(s.peek())) {
        s.advance();
        continue;
      }
      blocks.push(parseBlock(s));
    } catch (err) {
      s.notes.push(`${file}:${s.line}: parse error — ${(err as Error).message}`);
      while (s.guard() && !s.eof() && s.peek() !== '\n') s.advance();
    }
    if (s.i === loopAt) s.forceAdvance();
  }
  return { file, blocks, notes: s.notes };
}

/** Flatten a block's attributes + child blocks into a plain object for path lookup. */
export function hclBlockToObject(block: HclBlock): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const a of block.attributes) {
    out[a.name] = unwrapHcl(a.value);
  }
  for (const child of block.blocks) {
    const obj = hclBlockToObject(child);
    const key = child.blockType;
    if (out[key] === undefined) out[key] = obj;
    else if (Array.isArray(out[key])) (out[key] as unknown[]).push(obj);
    else out[key] = [out[key], obj];
  }
  return out;
}

export function unwrapHcl(v: HclValue): unknown {
  if (v.kind === 'list') return (v.raw as HclValue[]).map(unwrapHcl);
  if (v.kind === 'object') {
    const obj = v.raw as Record<string, HclValue>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(obj)) out[k] = unwrapHcl(obj[k]);
    return out;
  }
  return v.raw;
}
