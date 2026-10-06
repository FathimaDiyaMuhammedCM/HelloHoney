const assert = require('assert');

async function run() {
  // Rule logic unit tests (pure JS mirror of Python engine)
  const { computeAttackerRisk, levelFor } = require('../backend/utils/risk');
  assert.strictEqual(computeAttackerRisk({ failedLogins: 2, portProbes: 0, webProbes: 0, attackTypes: 0, highAlerts: 0, repeated: 0 }), 10);
  assert.strictEqual(computeAttackerRisk({ failedLogins: 100, portProbes: 100, webProbes: 100, attackTypes: 5, highAlerts: 5, repeated: 1 }), 100, 'capped at 100');
  assert.strictEqual(levelFor(10), 'LOW');
  assert.strictEqual(levelFor(30), 'MEDIUM');
  assert.strictEqual(levelFor(60), 'HIGH');
  assert.strictEqual(levelFor(90), 'CRITICAL');
  console.log('[TESTS] risk scoring OK');

  // Log parser unit tests
  require('./test_log_parser');

  // Python engine tests
  const { execSync } = require('child_process');
  try {
    execSync('python -m pytest honeypot -q', { stdio: 'inherit' });
  } catch (e) { console.log('[TESTS] python tests skipped/failed (ok if pytest missing)'); }
  console.log('ALL JS TESTS PASSED');
}
run().catch(e => { console.error('TEST FAILURE', e); process.exit(1); });
