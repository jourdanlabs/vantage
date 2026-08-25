// VANTAGE - Code Parsers
// Extract code elements from various languages

export interface ParsedEntity {
  type: 'function' | 'class' | 'variable' | 'constant' | 'import' | 'export' | 'type' | 'interface';
  name: string;
  line: number;
  depth: number;
  modifiers?: string[];
  signature?: string;
}

// TypeScript parser
export function parseTypeScript(content: string): ParsedEntity[] {
  const entities: ParsedEntity[] = [];
  const lines = content.split('\n');
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // Functions
    const funcMatch = trimmed.match(/(?:async\s+)?function\s+(\w+)\s*\((.*?)\)/);
    if (funcMatch) {
      entities.push({
        type: 'function',
        name: funcMatch[1],
        line: i + 1,
        depth: (line.match(/{/g) || []).length - (line.match(/}/g) || []).length,
        signature: funcMatch[2]
      });
      continue;
    }
    
    // Arrow functions
    const arrowMatch = trimmed.match(/(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\((.*?)\)\s*=>/);
    if (arrowMatch) {
      entities.push({
        type: 'function',
        name: arrowMatch[1],
        line: i + 1,
        depth: 0,
        signature: arrowMatch[2]
      });
      continue;
    }
    
    // Classes
    const classMatch = trimmed.match(/class\s+(\w+)(?:\s+extends\s+(\w+))?/);
    if (classMatch) {
      entities.push({
        type: 'class',
        name: classMatch[1],
        line: i + 1,
        depth: 0,
        modifiers: classMatch[2] ? ['extends ' + classMatch[2]] : []
      });
      continue;
    }
    
    // Interfaces
    const interfaceMatch = trimmed.match(/interface\s+(\w+)/);
    if (interfaceMatch) {
      entities.push({
        type: 'interface',
        name: interfaceMatch[1],
        line: i + 1,
        depth: 0
      });
      continue;
    }
    
    // Types
    const typeMatch = trimmed.match(/type\s+(\w+)\s*=/);
    if (typeMatch) {
      entities.push({
        type: 'type',
        name: typeMatch[1],
        line: i + 1,
        depth: 0
      });
      continue;
    }
    
    // Imports
    const importMatch = trimmed.match(/import\s+(?:(?:\{[^}]*\})|(\w+)|(?:\*\s+as\s+(\w+)))\s+from\s+['"]([^'"]+)['"]/);
    if (importMatch) {
      entities.push({
        type: 'import',
        name: importMatch[3],
        line: i + 1,
        depth: 0
      });
      continue;
    }
    
    // Exports
    const exportMatch = trimmed.match(/export\s+(?:default\s+)?(?:const|let|var|function|class|interface|type)\s+(\w+)/);
    if (exportMatch) {
      entities.push({
        type: 'export',
        name: exportMatch[1],
        line: i + 1,
        depth: 0
      });
      continue;
    }
  }
  
  return entities;
}

// JavaScript parser (subset of TS)
export function parseJavaScript(content: string): ParsedEntity[] {
  return parseTypeScript(content); // Same patterns work for JS
}

// Python parser
export function parsePython(content: string): ParsedEntity[] {
  const entities: ParsedEntity[] = [];
  const lines = content.split('\n');
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // Functions
    const funcMatch = trimmed.match(/^def\s+(\w+)\s*\((.*?)\)/);
    if (funcMatch) {
      entities.push({
        type: 'function',
        name: funcMatch[1],
        line: i + 1,
        depth: (line.match(/:/g) || []).length,
        signature: funcMatch[2]
      });
      continue;
    }
    
    // Classes
    const classMatch = trimmed.match(/^class\s+(\w+)(?:\((.*?)\))?:/);
    if (classMatch) {
      entities.push({
        type: 'class',
        name: classMatch[1],
        line: i + 1,
        depth: 0
      });
      continue;
    }
    
    // Imports
    const importMatch = trimmed.match(/^(?:from\s+(\S+)\s+)?import\s+(\S+)/);
    if (importMatch) {
      entities.push({
        type: 'import',
        name: importMatch[2] || importMatch[1],
        line: i + 1,
        depth: 0
      });
    }
  }
  
  return entities;
}

// Auto-detect language and parse
export function parseCode(content: string, filename: string): ParsedEntity[] {
  const ext = filename.toLowerCase().split('.').pop();
  
  switch (ext) {
    case 'ts':
    case 'tsx':
      return parseTypeScript(content);
    case 'js':
    case 'jsx':
      return parseJavaScript(content);
    case 'py':
      return parsePython(content);
    default:
      return parseTypeScript(content); // Default to TS
  }
}

export { parseHcl, hclBlockToObject } from './hcl';
export { parseDockerfile } from './dockerfile';
