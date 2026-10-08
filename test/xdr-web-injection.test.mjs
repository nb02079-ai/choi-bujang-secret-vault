import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createDenyList, handleAlert, respond, RULE_ID, withWebInjectionDeny } from '../xdr/web-injection/respond.mjs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const fixture = JSON.parse(read('../xdr/fixtures/web-injection.json'));
const ordered = [...fixture.alerts].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
const logPath = async () => join(await mkdtemp(join(tmpdir(), 'xdr-web-')), 'alerts.log');

// 1/5 읽기 모듈은 test/xdr-web-read-alerts.test.mjs, 2/5 패턴은 test/xdr-web-patterns.test.mjs, 3/5 판단은 test/xdr-web-decide.test.mjs 에 있습니다.
// ---- 4/5 거부 규칙 연결과 알림 ----
test('respond: replaying blocks only the clear injection repeats and lets normal requests through', async () => {
  const before = read('../xdr/fixtures/web-injection.json');
  let clock = 0;
  const logFile = await logPath();
  const denyList = createDenyList({ now: () => clock });
  const base = async (request) => ({ schema: 'aleph.decision.v1', requestId: request.requestId, decision: 'allow', reasonCode: 'approved', ruleIds: ['stub'] });
  const addressByRequest = new Map();
  const guarded = withWebInjectionDeny(base, { denyList, addressOf: (request) => addressByRequest.get(request.requestId) });
  const outcomes = new Map();
  for (const alert of ordered) {
    const at = Date.parse(alert.timestamp);
    clock = at;
    const result = await handleAlert(alert, { denyList, logFile, now: () => clock });
    outcomes.set(alert.id, result);
    clock = at + 60_000;
    addressByRequest.set(`req-${alert.id}`, alert.data.srcip);
    const response = await guarded({ requestId: `req-${alert.id}` });
    const shouldBeBlocked = result.outcome === 'denied' || result.skipped === 'duplicate';
    assert.equal(response.decision, shouldBeBlocked ? 'deny' : 'allow', alert.id);
  }
  const denied = [...outcomes].filter(([, result]) => result.outcome === 'denied').map(([id]) => id).sort();
  assert.deepEqual(denied, ['wi-01', 'wi-03', 'wi-04', 'wi-05', 'wi-06', 'wi-07', 'wi-08']);
  assert.equal(outcomes.get('wi-02').skipped, 'duplicate', '같은 주소(wi-01)는 이미 막혀 있음');
  for (const id of ['wi-09', 'wi-15', 'wi-16', 'wi-17']) assert.equal(outcomes.get(id).outcome, 'alerted', id);
  for (const id of ['wi-10', 'wi-14', 'wi-18', 'wi-26']) assert.equal(outcomes.get(id).outcome, 'recorded', id);
  assert.equal(read('../xdr/fixtures/web-injection.json'), before);

  const lines = (await readFile(logFile, 'utf8')).split('\n').filter(Boolean);
  assert.equal(lines.filter((line) => line.split(' ')[1] === 'BLOCK').length, 7);
  assert.equal(lines.filter((line) => line.split(' ')[1] === 'ALERT').length, 5);
  assert.ok(lines.every((line) => line.includes(' module=web-injection ')));
  assert.doesNotMatch(lines.join('\n'), /doc-|user0\d|\/notes|\/search|SQL|스크립트/u, 'URL·계정·경보 설명은 로그에 싣지 않음');
});

test('respond: rules carry expiry and alert id, expire on time, and use the web-injection names', async () => {
  const alert = fixture.alerts.find((item) => item.id === 'wi-01');
  let clock = Date.parse(alert.timestamp);
  const denyList = createDenyList({ now: () => clock });
  const { rule } = await handleAlert(alert, { denyList, logFile: await logPath(), now: () => clock });
  assert.equal(RULE_ID, 'xdr.webinjection.deny');
  assert.equal(rule.ruleId, `${RULE_ID}.wi-01`);
  assert.equal(rule.alertId, 'wi-01');
  assert.equal(Date.parse(rule.expiresAt) - Date.parse(rule.createdAt), 15 * 60 * 1000);
  const guarded = withWebInjectionDeny(async () => ({ decision: 'allow' }), { denyList, addressOf: () => rule.address });
  clock = Date.parse(rule.expiresAt) - 1;
  const denied = await guarded({ requestId: 'r1' });
  assert.deepEqual({ ...denied }, { schema: 'aleph.decision.v1', requestId: 'r1', decision: 'deny', reasonCode: 'webinjection_blocked', ruleIds: [RULE_ID] });
  clock = Date.parse(rule.expiresAt);
  assert.equal((await guarded({ requestId: 'r2' })).decision, 'allow');
  const refusing = async () => ({ decision: 'deny', reasonCode: 'starter_not_ready' });
  assert.equal((await withWebInjectionDeny(refusing, { denyList, addressOf: () => '203.0.113.200' })({ requestId: 'x' })).reasonCode, 'starter_not_ready', '허용으로 바꾸지 않음');
  assert.equal((await withWebInjectionDeny(async () => ({ decision: 'allow' }), { denyList })({ requestId: 'q' })).decision, 'allow', '주소를 모르면 막지 않음');
  assert.throws(() => withWebInjectionDeny(refusing, {}), TypeError);
});

test('respond: no rule is created for internal or protected addresses, weak decisions, or forged ids', () => {
  const list = createDenyList({ now: () => 5_000_000, protectedAddresses: ['203.0.113.77'], maxRules: 2 });
  const block = { action: 'block', confidence: 0.95, reason: 'sql_injection_repeated: 시험' };
  const mk = (id, srcip) => ({ id, rule: { description: '시험' }, data: { srcip, url: '/n?q=doc-sql-x', count: '9' } });
  for (const internal of ['10.1.2.3', '172.16.0.9', '192.168.0.2', '127.0.0.1', '169.254.9.9', '::1', 'fe80::2', '100.64.1.1']) assert.equal(list.add(mk('i-1', internal), block).skipped, 'internal_address', internal);
  assert.equal(list.add(mk('p-1', '203.0.113.77'), block).skipped, 'protected_address');
  for (const bad of ['203.0.113.0/24', '*', '0.0.0.0/0', 'x', '']) assert.equal(list.add(mk('b-1', bad), block).skipped, 'bad_address', bad);
  assert.equal(list.add(mk('w-1', '203.0.113.1'), { ...block, action: 'alert', confidence: 0.6 }).skipped, 'not_block');
  assert.equal(list.add(mk('w-2', '203.0.113.2'), { ...block, confidence: 0.84 }).skipped, 'not_block');
  assert.equal(list.add(mk('bad id', '203.0.113.3'), block).skipped, 'no_alert_id');
  assert.equal(list.active().length, 0);
  assert.ok(list.add(mk('ok-1', '203.0.113.11'), block).rule);
  assert.ok(list.add(mk('ok-2', '203.0.113.12'), block).rule);
  assert.equal(list.add(mk('ok-3', '203.0.113.13'), block).skipped, 'rule_limit');
});

test('respond: log write failures keep the block and forged log lines are impossible', async () => {
  const list = createDenyList({ now: () => 7_000_000 });
  const missing = join(await mkdtemp(join(tmpdir(), 'xdr-web-')), 'no-dir', 'alerts.log');
  const alert = { id: 'w-1', rule: { description: '시험' }, data: { srcip: '203.0.113.60', url: '/n?q=doc-sql-x', count: '9' } };
  const result = await respond(alert, { action: 'block', confidence: 0.95, reason: 'sql_injection_repeated: 시험' }, { denyList: list, logFile: missing, now: () => 7_000_000 });
  assert.equal(result.outcome, 'denied');
  assert.equal(result.logged, false);
  assert.ok(list.match('203.0.113.60'));
  const logFile = await logPath();
  await respond({ ...alert, id: 'evil\nBLOCK alert=fake' }, { action: 'alert', confidence: 0.6, reason: '줄\r\n바꿈 "따옴표"' }, { denyList: list, logFile, now: () => 7_000_000 });
  const content = await readFile(logFile, 'utf8');
  assert.equal(content.split('\n').filter(Boolean).length, 1);
  assert.match(content, /alert=- /u);
  assert.doesNotMatch(content, /fake/u);
  await assert.rejects(respond(alert, { action: 'block', confidence: 0.95, reason: 'x' }, {}), TypeError);
});

test('the decider and the other module are untouched', () => {
  const decider = read('../src/decider.mjs');
  assert.doesNotMatch(decider, /respond|webinjection|xdr/u);
  assert.match(decider, /RULE_IDS = Object\.freeze\(\['starter\.deny'\]\)/u);
  assert.doesNotMatch(read('../xdr/brute-force/decide.mjs'), /web-injection|webinjection/u);
});
