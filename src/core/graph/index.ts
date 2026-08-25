// VANTAGE - Code Graph System
// Tracks relationships between code elements

export interface CodeNode {
  id: string;
  type: 'function' | 'class' | 'variable' | 'import' | 'export';
  name: string;
  file: string;
  line: number;
  depth: number;
  children?: string[];
}

export interface CodeEdge {
  source: string;
  target: string;
  type: 'imports' | 'calls' | 'extends' | 'uses' | 'returns';
  weight: number;
}

export interface CodeGraph {
  nodes: CodeNode[];
  edges: CodeEdge[];
}

export function parseCodeFile(content: string, filename: string): CodeGraph {
  const nodes: CodeNode[] = [];
  const edges: CodeEdge[] = [];
  const lines = content.split('\n');
  
  let depth = 0;
  let nodeId = 0;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    if (trimmed.startsWith('function ') || trimmed.startsWith('async function ')) {
      const name = trimmed.match(/function\s+(\w+)/)?.[1] || 'anonymous';
      nodes.push({ id: `node_${nodeId++}`, type: 'function', name, file: filename, line: i + 1, depth });
    } else if (trimmed.startsWith('class ')) {
      const name = trimmed.match(/class\s+(\w+)/)?.[1] || 'Anonymous';
      nodes.push({ id: `node_${nodeId++}`, type: 'class', name, file: filename, line: i + 1, depth });
    } else if (trimmed.startsWith('import ') || trimmed.startsWith('import {') || trimmed.startsWith('import *')) {
      const name = trimmed.match(/import .+ from ['"]([^'"]+)['"]/)?.[1] || 'external';
      nodes.push({ id: `node_${nodeId++}`, type: 'import', name, file: filename, line: i + 1, depth: 0 });
    } else if (trimmed.startsWith('export ')) {
      const name = trimmed.match(/export\s+(?:const|let|var|function|class)\s+(\w+)/)?.[1] || 'export';
      nodes.push({ id: `node_${nodeId++}`, type: 'export', name, file: filename, line: i + 1, depth });
    }
    
    if (line.includes('{')) depth++;
    if (line.includes('}')) depth--;
  }
  
  return { nodes, edges };
}

export function findAnomalies(graph: CodeGraph): { node: CodeNode; anomaly: string; severity: number }[] {
  const anomalies: { node: CodeNode; anomaly: string; severity: number }[] = [];
  
  // Find functions with retry logic that's different from docs
  for (const node of graph.nodes) {
    if (node.name.includes('retry') || node.name.includes('payment')) {
      anomalies.push({
        node,
        anomaly: 'Potential retry logic - verify against docs',
        severity: 0.5
      });
    }
  }
  
  return anomalies;
}

export function buildGraph(files: string[]): CodeGraph {
  const allNodes: CodeNode[] = [];
  const allEdges: CodeEdge[] = [];
  
  for (const file of files) {
    const parsed = parseCodeFile(file, 'unknown');
    allNodes.push(...parsed.nodes);
    allEdges.push(...parsed.edges);
  }
  
  return { nodes: allNodes, edges: allEdges };
}