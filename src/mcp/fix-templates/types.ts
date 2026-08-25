// Fix-template contract — deterministic, gated-by-verify_fix patch generators.
//
// Every template implements `attempt(input)` and returns a proposed patch
// (unified-diff string) plus a brief rationale. The caller (generate_fix)
// is responsible for applying the patch to a temp copy and running
// verify_fix on the result. If verification fails, the template is treated
// as "did not apply"; never its responsibility to validate itself.
//
// Templates MUST be deterministic: identical input → identical output, forever.
// That's what makes the template path auditable vs. the LLM path.

export interface TemplateInput {
  /** Absolute or corpus-relative path to the source file. */
  filePath: string;
  /** Full current contents of the file. */
  fileContents: string;
  /** 1-indexed line number of the finding. */
  line: number;
  /** Normalized finding type (e.g. "null-safety", "error-boundary"). */
  findingType: string;
  /** Raw finding description — sometimes useful for disambiguating subtypes. */
  description: string;
}

export interface TemplateOutput {
  /** Whether a patch was successfully produced. */
  applied: boolean;
  /** Unified-diff patch string relative to the file. Empty if !applied. */
  patch: string;
  /** Short human-readable explanation of the transform applied. */
  rationale: string;
  /** Template identifier — surfaces to the caller for telemetry. */
  templateId: string;
  /** If !applied, why not. Helps LLM-fallback decide whether to try. */
  skipReason?: string;
}

export interface FixTemplate {
  /** Stable template identifier, e.g. "null-safety-optional-chaining". */
  id: string;
  /** Which finding types this template handles. */
  supportedFindingTypes: string[];
  /** Try to produce a patch for the given input. Must not throw. */
  attempt(input: TemplateInput): TemplateOutput;
}
