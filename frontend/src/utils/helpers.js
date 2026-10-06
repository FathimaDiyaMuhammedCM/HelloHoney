export function fmt(dt) {
  if (!dt) return '-';
  return new Date(dt).toLocaleString();
}
export function riskLevel(s) {
  if (s >= 76) return 'CRITICAL';
  if (s >= 51) return 'HIGH';
  if (s >= 21) return 'MEDIUM';
  return 'LOW';
}
