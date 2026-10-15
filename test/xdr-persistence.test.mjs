import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { decide } from '../xdr/persistence/decide.mjs';
import { readAlerts } from '../xdr/persistence/read-alerts.mjs';
import { createDenyList, handleAlert, respond, RULE_ID, withPersistenceIsolation } from '../xdr/persistence/respond.mjs';
import { decide as realDecide } from '../src/decider.mjs';

const fixture = JSON.parse(readFileSync(new URL('../xdr/fixtures/persistence.json', import.meta.url), 'utf8'));
const ordered = [...fixture.alerts].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
const patternsFile = readFileSync(new URL('../xdr/persistence/patterns.json', import.meta.url), 'utf8');
const decideSource = readFileSync(new URL('../xdr/persistence/decide.mjs', import.meta.url), 'utf8');
const logPath = async () => join(await mkdtemp(join(tmpdir(), 'xdr-ps-')), 'alerts.log');
const attackIds = ordered.filter((a) => a.rule.level >= 10).map((a) => a.id);
const normalIds = ordered.filter((a) => a.rule.level <= 3).map((a) => a.id);
const byId = (id) => fixture.alerts.find((a) => a.id === id);
// 경로는 실행할 때 조립합니다.
const tempPath = (name = 'x.exe') => ['C:', 'Users', 'u', 'AppData', 'Local', 'Temp', name].join(String.fromCharCode(92));
const alertWith = (id, srcip, description, extra = {}, level = 12) => ({ id, rule: { level, description }, data: { srcip, srcuser: 'user01', ...extra } });

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

test('read-alerts keeps one line per alert and never prints the executable path', async () => {
  const { alerts, rows, lines } = await readAlerts();
  assert.equal(alerts, 24);
  assert.equal(rows.length, alerts);
  assert.ok(lines.every((line) => !/\.(exe|cmd)\b|AppData|Temp\\/u.test(line)));
});

test('patterns: every pattern has a one-line evidence and decide.mjs carries the same list', () => {
  const file = JSON.parse(patternsFile);
  assert.equal(file.patterns.length, 3);
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

test('decide splits the fixture into block 8, alert 8, record 8 and does not change the alerts', () => {
  const before = JSON.stringify(fixture);
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) {
    const result = decide(alert);
    counts[result.action] += 1;
    assert.deepEqual(Object.keys(result).sort(), ['action', 'confidence', 'reason']);
    assert.ok(result.confidence >= 0 && result.confidence <= 1);
    assert.ok(!result.reason.includes('\n') && !/\.exe|AppData/u.test(result.reason));
    assert.equal(result.action, result.confidence >= 0.85 ? 'block' : result.confidence >= 0.5 ? 'alert' : 'record');
  }
  assert.deepEqual(counts, { block: 8, alert: 8, record: 8 });
  assert.deepEqual(fixture.alerts.filter((a) => decide(a).action === 'block').map((a) => a.id), attackIds);
  assert.deepEqual(fixture.alerts.filter((a) => decide(a).action === 'record').map((a) => a.id), normalIds);
  assert.equal(JSON.stringify(fixture), before);
});

test('decide: signed or existing items and negated phrases are not planted programs; unreadable alerts are only recorded', () => {
  const low = (description) => decide(alertWith('t', '203.0.113.10', description, {}, 2));
  for (const description of ['서명된 새 서비스가 등록됐습니다.', '기존 서비스가 서명된 채로 실행 중입니다.', '시작 프로그램 목록을 읽기만 했습니다.', '기존 예약 작업이 끝났습니다.']) {
    assert.equal(low(description).action, 'record', description);
  }
  assert.equal(decide(alertWith('t', '203.0.113.10', '서명 없는 새 서비스가 등록됐습니다.', {}, 2)).action, 'block');
  assert.equal(decide(alertWith('t', 'not-an-address', '서명 없는 새 서비스가 등록됐습니다.')).action, 'alert');
  assert.equal(decide(alertWith('t', '203.0.113.10', '서비스 등록은 없습니다.', { path: tempPath() }, 8)).action, 'alert');
  for (const bad of [null, undefined, {}, { data: [] }, { data: { path: 5 }, rule: {} }, alertWith('t', '203.0.113.10', '가'.repeat(5000))]) {
    assert.equal(decide(bad).action, 'record');
  }
});

test('replaying the fixture isolates only the clear attackers and lets normal requests through', async () => {
  const before = JSON.stringify(fixture);
  const { outcomes, logFile } = await replay();
  const rules = [...outcomes.values()].map((outcome) => outcome.rule).filter(Boolean);
  // ps-02 는 ps-01 과 같은 주소라 규칙이 겹치지 않고 알림으로 남습니다.
  assert.equal(rules.length, 7);
  assert.deepEqual(rules.map((rule) => rule.alertId).sort(), attackIds.filter((id) => id !== 'ps-02').sort());
  for (const rule of rules) {
    assert.equal(rule.type, 'deny');
    assert.match(rule.alertId, /^ps-\d+$/u);
    assert.ok(Date.parse(rule.expiresAt) > Date.parse(rule.createdAt));
  }
  assert.equal(outcomes.get('ps-02').skipped, 'duplicate');
  for (const id of normalIds) assert.equal(outcomes.get(id).outcome, 'recorded');
  const blocked = new Set(rules.map((rule) => rule.address));
  for (const alert of fixture.alerts.filter((a) => a.rule.level < 10)) {
    assert.ok(!blocked.has(alert.data.srcip), `${alert.id} 의 주소가 막히면 안 됩니다`);
  }
  assert.equal(JSON.stringify(fixture), before);

  const lines = (await readFile(logFile, 'utf8')).trim().split('\n');
  assert.equal(lines.length, 16);
  assert.ok(lines.every((line) => /^\d{4}-\d\d-\d\dT[\d:.]+Z (BLOCK|ALERT) module=persistence alert=ps-\d+ /u.test(line)));
  assert.ok(lines.every((line) => !/\.exe|AppData|user0|svc-lab/u.test(line)));
});

test('only the source address is isolated: the same account on another address still goes through', async () => {
  // 공격 경보에도 계정이 있으므로 계정 유무로 가리지 않습니다. 같은 계정 user01 이 평소 주소에서 보낸 요청은 막히지 않습니다.
  const first = byId('ps-01');
  let clock = Date.parse(first.timestamp);
  const denyList = createDenyList({ now: () => clock });
  const added = denyList.add(first, decide(first));
  assert.equal(first.data.srcuser, 'user01');
  assert.ok(added.rule);
  clock += 60_000;
  const baseline = { schema: 'aleph.decision.v1', requestId: 'r-1', service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id', deviceRegistered: true };
  const addressOf = (request) => request.__address;
  const connected = withPersistenceIsolation(realDecide, { denyList, addressOf });
  const isolated = await connected({ ...baseline, __address: first.data.srcip });
  assert.deepEqual({ decision: isolated.decision, ruleIds: isolated.ruleIds }, { decision: 'deny', ruleIds: [RULE_ID] });
  assert.equal(isolated.requestId, 'r-1');
  const usual = byId('ps-17');
  assert.equal(usual.data.srcuser, 'user01');
  assert.deepEqual(await connected({ ...baseline, __address: usual.data.srcip }), await realDecide(baseline));
  // 거부된 요청을 원래 판정기가 거부해도 허용으로 바뀌지 않습니다.
  assert.equal((await connected({ ...baseline, deviceRegistered: false, __address: usual.data.srcip })).decision, 'deny');
  // 주소를 모르는 기본 연결은 아무것도 막지 않습니다.
  assert.deepEqual(await withPersistenceIsolation(realDecide, { denyList })(baseline), await realDecide(baseline));
  assert.throws(() => withPersistenceIsolation(null, { denyList }), TypeError);
});

test('isolations expire, protected and internal addresses are never isolated, weak decisions never add a rule', async () => {
  let clock = Date.parse('2026-09-27T09:00:00+09:00');
  const list = createDenyList({ now: () => clock, ttlMs: 60_000, protectedAddresses: ['203.0.113.50'] });
  const block = { action: 'block', confidence: 0.9, reason: 'service_unsigned_new_or_changed: 시험' };
  assert.ok(list.add(alertWith('t-1', '203.0.113.60', '서명 없는 새 서비스'), block).rule);
  assert.ok(list.match('203.0.113.60'));
  clock += 61_000;
  assert.equal(list.match('203.0.113.60'), null);
  assert.equal(list.add(alertWith('t-2', '203.0.113.50', 'x'), block).skipped, 'protected_address');
  assert.equal(list.add(alertWith('t-3', '10.0.0.5', 'x'), block).skipped, 'internal_address');
  assert.equal(list.add(alertWith('t-4', '203.0.113.62', 'x'), { action: 'alert', confidence: 0.6, reason: '시험' }).skipped, 'not_block');
  assert.equal(list.add({ rule: { level: 12 }, data: { srcip: '203.0.113.63' } }, block).skipped, 'no_alert_id');
  assert.equal(list.add(alertWith('t-6', 'not-an-address', 'x'), block).skipped, 'bad_address');
  const logFile = await logPath();
  const result = await respond(alertWith('t-7', '10.0.0.5', 'x'), block, { denyList: list, logFile, now: () => clock });
  assert.equal(result.outcome, 'alerted');
  assert.match(await readFile(logFile, 'utf8'), /ALERT .*block_skipped=internal_address/u);
});
