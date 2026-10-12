// PROJECT-DEFINED HelloHoney Risk Score (not an industry standard).
function scoreForEvent(ev) {
  switch (ev.eventType) {
    case 'FAILED_LOGIN': return 5;
    case 'PORT_PROBE': return 10;
    case 'WEB_PROBE': return 10;
    case 'SUSPICIOUS_REQUEST': return 10;
    case 'CONNECTION': return 2;
    case 'TEST_LOGIN': return 5;
    default: return 1;
  }
}

function levelFor(score) {
  if (score >= 76) return 'CRITICAL';
  if (score >= 51) return 'HIGH';
  if (score >= 21) return 'MEDIUM';
  return 'LOW';
}

// HelloHoney Risk Score: capped at 100
function computeAttackerRisk({ failedLogins = 0, portProbes = 0, webProbes = 0, attackTypes = 0, highAlerts = 0, repeated = 0 }) {
  let score = failedLogins * 5 + portProbes * 10 + webProbes * 10;
  if (attackTypes > 1) score += 15;
  score += highAlerts * 20;
  if (repeated) score += 10;
  return Math.min(100, score);
}

module.exports = { scoreForEvent, levelFor, computeAttackerRisk };
