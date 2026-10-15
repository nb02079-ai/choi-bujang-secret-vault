import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { readAlerts } from '../xdr/exfiltration/read-alerts.mjs';
import { createDenyList, handleAlert, respond, RULE_ID, withExfiltrationBlock } from '../xdr/exfiltration/respond.mjs';
import { decide as realDecide } from '../src/decider.mjs';

const fixture = JSON.parse(readFileSync(new URL('../xdr/fixtures/exfiltration.json', import.meta.url), 'utf8'));
const ordered = [...fixture.alerts].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
const patternsFile = readFileSync(new URL('../xdr/exfiltration/patterns.json', import.meta.url), 'utf8');
const decideSource = readFileSync(new URL('../xdr/exfiltration/decide.mjs', import.meta.url), 'utf8');
const logPath = async () => join(await mkdtemp(join(tmpdir(), 'xdr-ex-')), 'alerts.log');
const attackIds = ordered.filter((a) => a.rule.level >= 10).map((a) => a.id);
const normalIds = ordered.filter((a) => a.rule.level <= 3).map((a) => a.id);
const byId = (id) => fixture.alerts.find((a) => a.id === id);
const alertWith = (id, dstip, description, bytes = '90000000', level = 12) => ({ id, rule: { level, description }, data: { srcip: '203.0.113.10', srcuser: 'user01', dstip, bytes } });

async function replay(options = {}) {
  let clock = 0;
  const logFile = options.logFile ?? await logPath();
  const denyList = createDenyList({ now: () => clock, ...options.list });
  const outcomes = new Map();
  for (const alert of ordered) {
    clock = Date.parse(alert.timestamp);
    outcomes.set(alert.id, await handleAlert(alert, { denyList, logFile, now: () => clock }));
  }
  return { denyList, logFile, outcomes };
}

test('read-alerts keeps one line per alert and never prints destination, size or counts', async () => {
  const { alerts, rows, lines } = await readAlerts();
  assert.equal(alerts, 30);
  assert.equal(rows.length, alerts);
  assert.ok(lines.every((line) => !/dstip|bytes|files|240000000|203\.0\.113\.50/u.test(line)));
});

test('patterns: every pattern has a one-line evidence and decide.mjs carries the same list', () => {
  const file = JSON.parse(patternsFile);
  assert.equal(file.patterns.length, 5);
  assert.equal(file.thresholds.largeBytes, 50000000);
  for (const pattern of file.patterns) {
    assert.ok(pattern.name && pattern.condition && pattern.source);
    assert.ok(typeof pattern.evidence === 'string' && pattern.evidence.length > 0 && !pattern.evidence.includes('\n'));
  }
  const copied = /PATTERNS-BEGIN\n.*? = (\{[\s\S]*\});\n\/\/ PATTERNS-END/u.exec(decideSource);
  assert.deepEqual(JSON.parse(copied[1]), file);
});

test('decide.mjs has no imports, no file or network access, and only decides', () => {
  assert.ok(!/^\s*import\b/mu.test(decideSource));
  assert.ok(!/\bimport\s*\(|\brequire\s*\(|\bfetch\s*\(|readFile|writeFile|appendFile|process\./u.test(decideSource));
});

test('decide splits the fixture into block 10, alert 10, record 10 and does not change the alerts', () => {
  const before = JSON.stringify(fixture);
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) {
    const result = decide(alert);
    counts[result.action] += 1;
    assert.deepEqual(Object.keys(result).sort(), ['action', 'confidence', 'reason']);
    assert.ok(result.confidence >= 0 && result.confidence <= 1);
    assert.ok(!result.reason.includes('\n') && !/user0|svc-lab|\d+\.\d+\.\d+\.\d+/u.test(result.reason));
    assert.equal(result.action, result.confidence >= 0.85 ? 'block' : result.confidence >= 0.5 ? 'alert' : 'record');
  }
  assert.deepEqual(counts, { block: 10, alert: 10, record: 10 });
  assert.deepEqual(fixture.alerts.filter((a) => decide(a).action === 'block').map((a) => a.id), attackIds);
  assert.deepEqual(fixture.alerts.filter((a) => decide(a).action === 'record').map((a) => a.id), normalIds);
  assert.equal(JSON.stringify(fixture), before);
});

test('decide: small, failed, negated or unreadable transfers are never blocked', () => {
  const to = '203.0.113.9';
  assert.equal(decide(alertWith('t', to, '처음 보는 목적지로 나갔습니다.')).action, 'block');
  assert.equal(decide(alertWith('t', to, '처음 보는 목적지로 나갔습니다.', 90000000)).action, 'block');
  assert.equal(decide(alertWith('t', to, '처음 보는 주소로 나갔습니다.', '400000', 6)).action, 'alert');
  assert.equal(decide(alertWith('t', to, '처음 보는 주소로 나갔습니다.', null)).action, 'alert');
  assert.equal(decide(alertWith('t', to, '처음 보는 주소로 나갔습니다.', '9e9x', 7)).action, 'alert');
  assert.equal(decide(alertWith('t', to, '전송이 실패했습니다. 처음 보는 주소입니다.', '90000000', 7)).action, 'alert');
  assert.equal(decide(alertWith('t', to, '외부 전송은 아직 없습니다.', '90000000', 5)).action, 'alert');
  assert.equal(decide(alertWith('t', 'x', '처음 보는 목적지로 나갔습니다.')).action, 'alert');
  assert.equal(decide(alertWith('t', undefined, '처음 보는 목적지로 나갔습니다.')).action, 'alert');
  assert.equal(decide(alertWith('t', '192.0.2.10', '내 메모 한 건을 읽었습니다.', '2400', 3)).action, 'record');
  for (const bad of [null, undefined, {}, { data: [] }, alertWith('t', to, '가'.repeat(5000))]) {
    assert.equal(decide(bad).action, 'record');
  }
});

test('replaying the fixture blocks only the clear destinations and creates no rule from other alerts', async () => {
  const before = JSON.stringify(fixture);
  const { outcomes, logFile } = await replay();
  const rules = [...outcomes.values()].map((outcome) => outcome.rule).filter(Boolean);
  // 같은 목적지가 다시 나오는 ex-03·ex-04 는 앞선 규칙이 만료된 뒤라 새 규칙이 됩니다.
  assert.equal(rules.length, 10);
  assert.deepEqual(rules.map((rule) => rule.alertId).sort(), [...attackIds].sort());
  for (const rule of rules) {
    assert.equal(rule.type, 'deny');
    assert.match(rule.alertId, /^ex-\d+$/u);
    assert.ok(Date.parse(rule.expiresAt) > Date.parse(rule.createdAt));
  }
  for (const id of normalIds) assert.equal(outcomes.get(id).outcome, 'recorded');
  for (const alert of fixture.alerts.filter((a) => a.rule.level < 10)) assert.ok(!outcomes.get(alert.id).rule);
  const blocked = new Set(rules.map((rule) => rule.address));
  for (const alert of fixture.alerts.filter((a) => a.rule.level < 10 && a.data.dstip)) {
    assert.ok(!blocked.has(alert.data.dstip), `${alert.id} 의 목적지가 막히면 안 됩니다`);
  }
  assert.equal(JSON.stringify(fixture), before);

  const lines = (await readFile(logFile, 'utf8')).trim().split('\n');
  assert.equal(lines.length, 20);
  assert.ok(lines.every((line) => /^\d{4}-\d\d-\d\dT[\d:.]+Z (BLOCK|ALERT) module=exfiltration alert=ex-\d+ /u.test(line)));
  assert.ok(lines.every((line) => !/user0|svc-lab|srcip/u.test(line)));
});

test('only the blocked destination is denied: other destinations get the original decision', async () => {
  const first = byId('ex-01');
  let clock = Date.parse(first.timestamp);
  const denyList = createDenyList({ now: () => clock });
  assert.ok(denyList.add(first, decide(first)).rule);
  clock += 60_000;
  const baseline = { schema: 'aleph.decision.v1', requestId: 'r-1', service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id', deviceRegistered: true };
  const destinationOf = (request) => request.__destination;
  const connected = withExfiltrationBlock(realDecide, { denyList, destinationOf });
  const denied = await connected({ ...baseline, __destination: first.data.dstip });
  assert.deepEqual({ decision: denied.decision, ruleIds: denied.ruleIds }, { decision: 'deny', ruleIds: [RULE_ID] });
  assert.equal(denied.requestId, 'r-1');
  for (const usual of ['192.0.2.10', '198.51.100.10', '203.0.113.99']) {
    assert.deepEqual(await connected({ ...baseline, __destination: usual }), await realDecide(baseline));
  }
  // 거부된 요청을 원래 판정기가 거부해도 허용으로 바뀌지 않습니다.
  assert.equal((await connected({ ...baseline, deviceRegistered: false, __destination: '192.0.2.10' })).decision, 'deny');
  // 목적지를 모르는 기본 연결은 아무것도 막지 않습니다.
  assert.deepEqual(await withExfiltrationBlock(realDecide, { denyList })(baseline), await realDecide(baseline));
  assert.throws(() => withExfiltrationBlock(null, { denyList }), TypeError);
  clock += 16 * 60_000;
  assert.deepEqual(await connected({ ...baseline, __destination: first.data.dstip }), await realDecide(baseline));
});

test('blocks expire, protected and internal destinations are never blocked, weak decisions never add a rule', async () => {
  let clock = Date.parse('2026-09-27T09:00:00+09:00');
  const list = createDenyList({ now: () => clock, ttlMs: 60_000, protectedAddresses: ['203.0.113.70'] });
  const block = { action: 'block', confidence: 0.9, reason: 'large_transfer_to_unfamiliar_destination: 시험' };
  assert.ok(list.add(alertWith('t-1', '203.0.113.60', 'x'), block).rule);
  assert.ok(list.match('203.0.113.60'));
  clock += 61_000;
  assert.equal(list.match('203.0.113.60'), null);
  assert.equal(list.add(alertWith('t-2', '203.0.113.70', 'x'), block).skipped, 'protected_address');
  assert.equal(list.add(alertWith('t-3', '10.0.0.5', 'x'), block).skipped, 'internal_address');
  assert.equal(list.add(alertWith('t-4', '203.0.113.62', 'x'), { action: 'alert', confidence: 0.6, reason: '시험' }).skipped, 'not_block');
  assert.equal(list.add({ rule: { level: 12 }, data: { dstip: '203.0.113.63' } }, block).skipped, 'no_alert_id');
  assert.equal(list.add(alertWith('t-6', 'not-an-address', 'x'), block).skipped, 'bad_address');
  // 기본 지킬 목적지(자료실·수업 자료 주소)는 목록을 따로 주지 않아도 막히지 않습니다.
  const defaults = createDenyList({ now: () => clock });
  assert.equal(defaults.add(alertWith('t-7', '192.0.2.10', 'x'), block).skipped, 'protected_address');
  assert.equal(defaults.add(alertWith('t-8', '198.51.100.10', 'x'), block).skipped, 'protected_address');
  const logFile = await logPath();
  const result = await respond(alertWith('t-9', '10.0.0.5', 'x'), block, { denyList: list, logFile, now: () => clock });
  assert.equal(result.outcome, 'alerted');
  assert.match(await readFile(logFile, 'utf8'), /ALERT .*block_skipped=internal_address/u);
});
