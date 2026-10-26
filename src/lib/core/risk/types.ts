export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Certainty = "confirmed" | "potential" | "informational" | "not_checkable";
export type Confidence = "high" | "medium" | "low";
export type FindingCategory = "email" | "dns" | "tls" | "web" | "exposure" | "vulnerability" | "breach" | "asset" | "brand";
export type FindingStatus = "new" | "investigating" | "action_required" | "resolved" | "accepted_risk" | "false_positive";

export const OPEN_STATUSES: FindingStatus[] = ["new", "investigating", "action_required"];
export const CLOSED_STATUSES: FindingStatus[] = ["resolved", "accepted_risk", "false_positive"];

/** Rohbeobachtung eines Adapters – noch ohne Bewertung. */
export interface Observation {
  ruleId: string;
  /** Betroffenes Asset (Hostname oder IP) */
  asset: string;
  /** Unterscheidet mehrere Befunde derselben Regel am selben Asset (z. B. Port, CVE, Breach-Name) */
  discriminator?: string;
  /** Fakten, die die Bewertung beeinflussen (deterministisch ausgewertet) */
  facts: Record<string, unknown>;
  /** Nachweis (gekürzt, ohne personenbezogene Daten) */
  evidence: Record<string, unknown>;
  sourceRef?: string;
}

/** Eine Prüfung, die für ein Asset vollständig und erfolgreich durchgeführt wurde. */
export interface Coverage {
  asset: string;
  check: string;
}

export interface DocLink {
  label: string;
  url: string;
}

export interface Evaluation {
  severity: Severity;
  reasons: string[];
}

export interface RuleDefinition {
  id: string;
  check: string;
  category: FindingCategory;
  certainty: Certainty;
  confidence: Confidence;
  title: (o: Observation) => string;
  evaluate: (o: Observation) => Evaluation;
  summary: (o: Observation) => string;
  businessImpact: (o: Observation) => string;
  recommendation: (o: Observation) => string;
  technicalDetails: (o: Observation) => string;
  verificationSteps?: (o: Observation) => string;
  docs: DocLink[];
}

/** Normalisierter Befund, bereit zur Speicherung. */
export interface NormalizedFinding {
  fingerprint: string;
  ruleId: string;
  check: string;
  category: FindingCategory;
  source: string;
  sourceRef: string | null;
  asset: string;
  title: string;
  summary: string;
  businessImpact: string;
  recommendation: string;
  technicalDetails: string;
  verificationSteps: string | null;
  docs: DocLink[];
  evidence: Record<string, unknown>;
  severity: Severity;
  certainty: Certainty;
  confidence: Confidence;
  priorityScore: number;
  priorityReasons: string[];
}
