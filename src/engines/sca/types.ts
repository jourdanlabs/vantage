/** SCA manifest parse types. Matching / OSV / CVE lookup is not built. */

export type Ecosystem = 'npm' | 'pypi';

export type SourceKind =
  | 'package.json'
  | 'package-lock.json'
  | 'requirements.txt'
  | 'Pipfile.lock';

export interface ParsedDep {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  sourceFile: string;
  sourceKind: SourceKind;
}

export type ScaEcosystem = Ecosystem;
export type ManifestSourceKind = SourceKind;
