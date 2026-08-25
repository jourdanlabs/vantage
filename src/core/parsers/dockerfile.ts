// Dockerfile config-tree parser (v1)
// Single file only. Instructions, flags, values. No multi-stage graph tracing.

export interface DockerInstruction {
  instruction: string;
  flags: Record<string, string | boolean>;
  args: string;
  values: string[];
  startLine: number;
  /** FROM only */
  image?: string;
  tag?: string;
  digest?: string;
  stage?: string;
  /** True when FROM has no explicit :tag (Docker defaults to latest). */
  tagOmitted?: boolean;
}

export interface DockerDocument {
  file: string;
  instructions: DockerInstruction[];
  notes: string[];
}

const INSTRUCTION_RE = /^(FROM|RUN|CMD|LABEL|MAINTAINER|EXPOSE|ENV|ADD|COPY|ENTRYPOINT|VOLUME|USER|WORKDIR|ARG|ONBUILD|STOPSIGNAL|HEALTHCHECK|SHELL)\b/i;

function splitFlags(rest: string): { flags: Record<string, string | boolean>; rest: string } {
  const flags: Record<string, string | boolean> = {};
  let i = 0;
  const s = rest.trim();
  while (i < s.length) {
    while (s[i] === ' ' || s[i] === '\t') i++;
    if (s[i] === '-' && s[i + 1] === '-') {
      let j = i + 2;
      while (j < s.length && s[j] !== ' ' && s[j] !== '\t' && s[j] !== '=') j++;
      const key = s.slice(i + 2, j);
      if (s[j] === '=') {
        j++;
        let val = '';
        if (s[j] === '"' || s[j] === "'") {
          const q = s[j++];
          while (j < s.length && s[j] !== q) val += s[j++];
          if (s[j] === q) j++;
        } else {
          while (j < s.length && s[j] !== ' ' && s[j] !== '\t') val += s[j++];
        }
        flags[key] = val;
      } else {
        flags[key] = true;
      }
      i = j;
      continue;
    }
    break;
  }
  return { flags, rest: s.slice(i).trim() };
}

function parseFromImage(args: string): { image: string; tag?: string; digest?: string; stage?: string; tagOmitted?: boolean } {
  // image[:tag][@digest] [AS name]
  let stage: string | undefined;
  let body = args.trim();
  const asMatch = body.match(/\s+[Aa][Ss]\s+(\S+)\s*$/);
  if (asMatch) {
    stage = asMatch[1];
    body = body.slice(0, asMatch.index).trim();
  }
  const at = body.lastIndexOf('@');
  if (at > 0) {
    return { image: body.slice(0, at), digest: body.slice(at + 1), stage };
  }
  // tag is the last : after the last /
  const slash = body.lastIndexOf('/');
  const colon = body.lastIndexOf(':');
  if (colon > slash) {
    return { image: body.slice(0, colon), tag: body.slice(colon + 1), stage };
  }
  // Docker default tag is latest when omitted (AVD-DS-0001 treats omitted as latest).
  // tagOmitted distinguishes DL3006 (unpinned) from DL3007 (explicit latest).
  return { image: body, tag: 'latest', tagOmitted: true, stage };
}

function tokenizeArgs(args: string): string[] {
  const out: string[] = [];
  let i = 0;
  const s = args;
  while (i < s.length) {
    while (s[i] === ' ' || s[i] === '\t') i++;
    if (i >= s.length) break;
    if (s[i] === '"' || s[i] === "'") {
      const q = s[i++];
      let tok = '';
      while (i < s.length && s[i] !== q) tok += s[i++];
      if (s[i] === q) i++;
      out.push(tok);
      continue;
    }
    if (s[i] === '[') {
      // JSON array — keep as one token plus split inners
      const start = i;
      let depth = 0;
      while (i < s.length) {
        if (s[i] === '[') depth++;
        if (s[i] === ']') {
          depth--;
          i++;
          if (depth === 0) break;
          continue;
        }
        i++;
      }
      out.push(s.slice(start, i));
      continue;
    }
    let tok = '';
    while (i < s.length && s[i] !== ' ' && s[i] !== '\t') tok += s[i++];
    out.push(tok);
  }
  return out;
}

export function parseDockerfile(content: string, file = ''): DockerDocument {
  const raw = content.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const physical = raw.split('\n');
  const instructions: DockerInstruction[] = [];
  const notes: string[] = [];

  let i = 0;
  while (i < physical.length) {
    const startLine = i + 1;
    let line = physical[i];
    const trimmedLead = line.trim();
    if (!trimmedLead || trimmedLead.startsWith('#')) {
      i++;
      continue;
    }
    // continuation \
    while (line.trimEnd().endsWith('\\') && i + 1 < physical.length) {
      line = line.trimEnd().slice(0, -1) + physical[i + 1];
      i++;
    }
    const trimmed = line.trim();
    const m = trimmed.match(INSTRUCTION_RE);
    if (!m) {
      notes.push(`${file}:${startLine}: not an instruction — ${trimmed.slice(0, 40)}`);
      i++;
      continue;
    }
    const instruction = m[1].toUpperCase();
    const after = trimmed.slice(m[0].length).trim();
    const { flags, rest } = splitFlags(after);
    const inst: DockerInstruction = {
      instruction,
      flags,
      args: rest,
      values: tokenizeArgs(rest),
      startLine,
    };
    if (instruction === 'FROM') {
      const parsed = parseFromImage(rest);
      inst.image = parsed.image;
      inst.tag = parsed.tag;
      inst.digest = parsed.digest;
      inst.stage = parsed.stage;
      inst.tagOmitted = parsed.tagOmitted;
    }
    if (instruction === 'USER') {
      inst.values = rest ? [rest] : [];
    }
    instructions.push(inst);
    i++;
  }

  return { file, instructions, notes };
}
