const { parse } = require('../backend/services/logParser');
const assert = require('assert');

// 1. Syslog RFC 3164
const s1 = 'Sep 28 10:15:32 honeypot sshd[1234]: Failed password for root from 192.168.1.50 port 44322 ssh2';
const res1 = parse(s1);
assert.strictEqual(res1.length, 1);
assert.strictEqual(res1[0].eventType, 'FAILED_LOGIN');
assert.strictEqual(res1[0].sourceIP, '192.168.1.50');
assert.strictEqual(res1[0].username, 'root');
console.log('✓ Test 1: Syslog RFC 3164 passed');

// 2. ISO Syslog
const s2 = '2026-09-28T10:15:32.000Z honeypot sshd[1234]: Accepted password for admin from 10.0.0.5 port 22';
const res2 = parse(s2);
assert.strictEqual(res2.length, 1);
assert.strictEqual(res2[0].eventType, 'TEST_LOGIN');
assert.strictEqual(res2[0].sourceIP, '10.0.0.5');
assert.strictEqual(res2[0].username, 'admin');
console.log('✓ Test 2: ISO Syslog passed');

// 3. JSON Array
const s3 = JSON.stringify([
  { sourceIP: '192.168.1.99', eventType: 'FAILED_LOGIN', username: 'guest' },
  { sourceIP: '192.168.1.100', eventType: 'WEB_PROBE', service: 'HTTP' }
], null, 2);
const res3 = parse(s3);
assert.strictEqual(res3.length, 2);
assert.strictEqual(res3[0].sourceIP, '192.168.1.99');
assert.strictEqual(res3[1].eventType, 'WEB_PROBE');
console.log('✓ Test 3: JSON Array passed');

// 4. CSV with headers
const s4 = 'Timestamp,Source_IP,Service,EventType,Status\n2026-09-28T10:00:00Z,192.168.1.100,SSH,FAILED_LOGIN,failed';
const res4 = parse(s4);
assert.strictEqual(res4.length, 1);
assert.strictEqual(res4[0].sourceIP, '192.168.1.100');
assert.strictEqual(res4[0].eventType, 'FAILED_LOGIN');
console.log('✓ Test 4: CSV with headers passed');

// 5. Apache Web Log
const s5 = '192.168.1.77 - - [28/Sep/2026:10:00:00 +0000] "GET /wp-admin/login.php HTTP/1.1" 404 123';
const res5 = parse(s5);
assert.strictEqual(res5.length, 1);
assert.strictEqual(res5[0].sourceIP, '192.168.1.77');
assert.strictEqual(res5[0].eventType, 'WEB_PROBE');
console.log('✓ Test 5: Web probe passed');

console.log('\nALL 5 LOG PARSER TESTS PASSED!');
