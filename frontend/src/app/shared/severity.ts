// Case-insensitive so npm's lowercase and Trivy's uppercase severities sort the same way. "medium" and "moderate" are the same tier under different vocabularies.
const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  moderate: 2,
  low: 3,
  unknown: 4,
}

export function severityRank(severity: string): number {
  return SEVERITY_RANK[severity.toLowerCase()] ?? Number.MAX_SAFE_INTEGER
}

export function bySeverityDesc<T>(getSeverity: (item: T) => string): (a: T, b: T) => number {
  return (a, b) => severityRank(getSeverity(a)) - severityRank(getSeverity(b))
}
