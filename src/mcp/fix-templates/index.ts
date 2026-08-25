// Fix-template registry. Add new templates here and they're picked up
// automatically by generate_fix.

import { FixTemplate } from './types';
import { NullSafetyTemplate } from './null-safety';
import { ErrorBoundaryTemplate } from './error-boundary';
import { HardcodedSecretTemplate } from './hardcoded-secret';

export const ALL_TEMPLATES: FixTemplate[] = [
  NullSafetyTemplate,
  ErrorBoundaryTemplate,
  HardcodedSecretTemplate,
];

export function templatesForType(findingType: string): FixTemplate[] {
  return ALL_TEMPLATES.filter(t =>
    t.supportedFindingTypes.includes(findingType)
  );
}

export * from './types';
