/** Converts backend risk_score (0=best, 100=worst) to posture score (0=worst, 100=best). */
export function toPostureScore(scan: { risk_score?: number | null } | null): number {
  if (!scan || scan.risk_score == null) return 0;
  const cap = 100; // matches backend risk cap in config/ready.yaml
  return Math.max(0, cap - scan.risk_score);
}
