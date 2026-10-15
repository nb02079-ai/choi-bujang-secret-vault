import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { decide } from '../xdr/privilege/decide.mjs';
import { readAlerts } from '../xdr/privilege/read-alerts.mjs';
import { createDenyList, handleAlert, respond, RULE_ID, withPrivilegeRevoke } from '../xdr/privilege/respond.mjs';
import { decide as realDecide } from '../src/decider.mjs';

const fixture = JSON.parse(readFileSync(new URL('../xdr/fixtures/privilege.json', import.meta.url), 'utf8'));
const ordered = [...fixture.alerts].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
const patternsFile = readFileSync(new URL('../xdr/privilege/patterns.json', import.meta.url), 'utf8');
const decideSource = readFileSync(new URL('../xdr/privilege/decide.mjs', import.meta.url), 'utf8');
const logPath = async () => join(await mkdtemp(join(tmpdir(), 'xdr-pv-')), 'alerts.log');
const attackIds = ordered.filter((a) => a.rule.level >= 10).map((a) => a.id);
const normalIds = ordered.filter((a) => a.rule.level <= 3).map((a) => a.id);
const byId = (id) => fixture.alerts.find((a) => a.id === id);
const alertWith = (id, srcuser, description, level = 12) => ({ id, rule: { level, description }, data: { srcip: '203.0.113.10', srcuser } });

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

test('read-alerts keeps one line per alert and never prints group names', async () => {
  const { alerts, rows, lines } = await readAlerts();
  assert.equal(alerts, 26);
  assert.equal(rows.length, alerts);
  assert.ok(lines.every((line) => !/administrators|project-week3|lab-notes|class-readers/u.test(line)));
});

test('patterns: every pattern has a one-line evidence and decide.mjs carries the same list', () => {
  const file = JSON.parse(patternsFile);
  assert.equal(file.patterns.length, 4);
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

test('decide splits the fixture into block 9, alert 8, record 9 and does not change the alerts', () => {
  const before = JSON.stringify(fixture);
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) {
    const result = decide(alert);
    counts[result.action] += 1;
    assert.deepEqual(Object.keys(result).sort(), ['action', 'confidence', 'reason']);
    assert.ok(result.confidence >= 0 && result.confidence <= 1);
    assert.ok(!result.reason.includes('\n') && !/user0|admin01|svc-lab/u.test(result.reason));
    assert.equal(result.action, result.confidence >= 0.85 ? 'block' : result.confidence >= 0.5 ? 'alert' : 'record');
  }
  assert.deepEqual(counts, { block: 9, alert: 8, record: 9 });
  assert.deepEqual(fixture.alerts.filter((a) => decide(a).action === 'block').map((a) => a.id), attackIds);
  assert.deepEqual(fixture.alerts.filter((a) => decide(a).action === 'record').map((a) => a.id), normalIds);
  assert.equal(JSON.stringify(fixture), before);
});

test('decide: negated phrases, failed attempts and unreadable alerts are never blocked', () => {
  assert.equal(decide(alertWith('t', 'user01', '관리자 그룹에 추가되지 않았습니다.', 2)).action, 'record');
  assert.equal(decide(alertWith('t', 'user01', '처음 보는 주소에서 관리자 명령이 실패했습니다.', 7)).action, 'alert');
  assert.equal(decide(alertWith('t', 'user01', '수업 중 관리자 명령이 한 번 실행됐습니다.', 5)).action, 'alert');
  assert.equal(decide(alertWith('t', 'user01', '관리자 그룹에 추가됐습니다.')).action, 'block');
  assert.equal(decide(alertWith('t', 'a b', '관리자 그룹에 추가됐습니다.')).action, 'alert');
  assert.equal(decide({ rule: { level: 12, description: '관리자 그룹에 추가됐습니다.' }, data: {} }).action, 'alert');
  for (const bad of [null, undefined, {}, { data: [] }, alertWith('t', 'user01', '가'.repeat(5000))]) {
    assert.equal(decide(bad).action, 'record');
  }
});

test('replaying the fixture revokes only the clear attackers and creates no rule from normal alerts', async () => {
  const before = JSON.stringify(fixture);
  const { outcomes, logFile } = await replay();
  const rules = [...outcomes.values()].map((outcome) => outcome.rule).filter(Boolean);
  // pv-02 는 pv-01 과 같은 계정이라 규칙이 겹치지 않고 알림으로 남습니다.
  assert.equal(rules.length, 8);
  assert.deepEqual(rules.map((rule) => rule.alertId).sort(), attackIds.filter((id) => id !== 'pv-02').sort());
  for (const rule of rules) {
    assert.equal(rule.type, 'deny');
    assert.match(rule.alertId, /^pv-\d+$/u);
    assert.ok(Date.parse(rule.expiresAt) > Date.parse(rule.createdAt));
  }
  assert.equal(outcomes.get('pv-02').skipped, 'duplicate');
  for (const id of normalIds) assert.equal(outcomes.get(id).outcome, 'recorded');
  for (const alert of fixture.alerts.filter((a) => a.rule.level < 10)) assert.ok(!outcomes.get(alert.id).rule);
  const revoked = new Set(rules.map((rule) => rule.account));
  assert.ok(!revoked.has('admin01') && !revoked.has('svc-lab'));
  assert.equal(JSON.stringify(fixture), before);

  const lines = (await readFile(logFile, 'utf8')).trim().split('\n');
  assert.equal(lines.length, 17);
  assert.ok(lines.every((line) => /^\d{4}-\d\d-\d\dT[\d:.]+Z (BLOCK|ALERT) module=privilege alert=pv-\d+ /u.test(line)));
  assert.ok(lines.every((line) => !/user0|admin01|svc-lab|203\.0|198\.51|192\.0/u.test(line)));
});

test('only the revoked account is denied: other accounts get the original decision', async () => {
  const first = byId('pv-01');
  let clock = Date.parse(first.timestamp);
  const denyList = createDenyList({ now: () => clock });
  assert.ok(denyList.add(first, decide(first)).rule);
  clock += 60_000;
  const baseline = { schema: 'aleph.decision.v1', requestId: 'r-1', service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id', deviceRegistered: true };
  const accountOf = (request) => request.__account;
  const connected = withPrivilegeRevoke(realDecide, { denyList, accountOf });
  const denied = await connected({ ...baseline, __account: first.data.srcuser });
  assert.deepEqual({ decision: denied.decision, ruleIds: denied.ruleIds }, { decision: 'deny', ruleIds: [RULE_ID] });
  assert.equal(denied.requestId, 'r-1');
  assert.deepEqual(await connected({ ...baseline, __account: 'user02' }), await realDecide(baseline));
  assert.deepEqual(await connected({ ...baseline, __account: 'admin01' }), await realDecide(baseline));
  // 거부된 요청을 원래 판정기가 거부해도 허용으로 바뀌지 않습니다.
  assert.equal((await connected({ ...baseline, deviceRegistered: false, __account: 'user02' })).decision, 'deny');
  // 계정을 모르는 기본 연결은 아무것도 막지 않습니다.
  assert.deepEqual(await withPrivilegeRevoke(realDecide, { denyList })(baseline), await realDecide(baseline));
  assert.throws(() => withPrivilegeRevoke(null, { denyList }), TypeError);
  clock += 16 * 60_000;
  assert.deepEqual(await connected({ ...baseline, __account: first.data.srcuser }), await realDecide(baseline));
});

test('revocations expire, protected accounts are never revoked, weak decisions never add a rule', async () => {
  let clock = Date.parse('2026-09-27T09:00:00+09:00');
  const list = createDenyList({ now: () => clock, ttlMs: 60_000, protectedAccounts: ['ops-lead'] });
  const block = { action: 'block', confidence: 0.9, reason: 'admin_group_added: 시험' };
  assert.ok(list.add(alertWith('t-1', 'user51', 'x'), block).rule);
  assert.ok(list.match('user51'));
  clock += 61_000;
  assert.equal(list.match('user51'), null);
  assert.equal(list.add(alertWith('t-2', 'ops-lead', 'x'), block).skipped, 'protected_account');
  assert.equal(list.add(alertWith('t-3', 'a b', 'x'), block).skipped, 'bad_account');
  assert.equal(list.add(alertWith('t-4', 'user52', 'x'), { action: 'alert', confidence: 0.6, reason: '시험' }).skipped, 'not_block');
  assert.equal(list.add({ rule: { level: 12 }, data: { srcuser: 'user53' } }, block).skipped, 'no_alert_id');
  const logFile = await logPath();
  const result = await respond(alertWith('t-7', 'ops-lead', 'x'), block, { denyList: list, logFile, now: () => clock });
  assert.equal(result.outcome, 'alerted');
  assert.match(await readFile(logFile, 'utf8'), /ALERT .*block_skipped=protected_account/u);
});
