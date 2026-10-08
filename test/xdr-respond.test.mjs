import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { decide } from '../xdr/brute-force/decide.mjs';
import { createDenyList, handleAlert, respond, RULE_ID, withBruteForceDeny } from '../xdr/brute-force/respond.mjs';

const fixture = JSON.parse(readFileSync(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
const ordered = [...fixture.alerts].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
const BLOCK_DECISION = { action: 'block', confidence: 0.95, reason: 'rapid_failures_same_source: 시험' };
const alertWith = (id, srcip, extra = {}) => ({ id, rule: { description: '실패' }, data: { srcip, srcuser: 'user01', count: '90' }, ...extra });
const logPath = async () => join(await mkdtemp(join(tmpdir(), 'xdr-respond-')), 'alerts.log');

// 시험 경보를 시간 순서대로 다시 흘립니다. 경보 시각을 시계로 씁니다.
async function replay(options = {}) {
  let clock = 0;
  const logFile = options.logFile ?? await logPath();
  const denyList = createDenyList({ now: () => clock, ...options.list });
  const outcomes = new Map();
  for (const alert of ordered) {
    clock = Date.parse(alert.timestamp);
    outcomes.set(alert.id, await handleAlert(alert, { denyList, logFile, now: () => clock }));
  }
  return { denyList, logFile, outcomes, setClock: (ms) => { clock = ms; }, at: (id) => Date.parse(ordered.find((a) => a.id === id).timestamp) };
}

test('replaying the fixture blocks only the clear attacks and lets normal requests through', async () => {
  const before = JSON.stringify(fixture);
  let clock = 0;
  const logFile = await logPath();
  const denyList = createDenyList({ now: () => clock });
  // 판정기 대신 모두 허용하는 가짜 판정기를 감싸서, 어떤 요청이 거부로 바뀌는지만 봅니다.
  const base = async (request) => ({ schema: 'aleph.decision.v1', requestId: request.requestId, decision: 'allow', reasonCode: 'approved', ruleIds: ['stub'] });
  const addressByRequest = new Map();
  const guarded = withBruteForceDeny(base, { denyList, addressOf: (request) => addressByRequest.get(request.requestId) });
  const outcomes = new Map();
  for (const alert of ordered) {
    const at = Date.parse(alert.timestamp);
    clock = at;
    const result = await handleAlert(alert, { denyList, logFile, now: () => clock });
    outcomes.set(alert.id, result);
    // 처리 직후(1분 뒤) 이 경보의 주소에서 온 요청이 어떻게 되는지 봅니다.
    clock = at + 60_000;
    addressByRequest.set(`req-${alert.id}`, alert.data.srcip);
    const response = await guarded({ requestId: `req-${alert.id}` });
    const shouldBeBlocked = result.outcome === 'denied' || result.skipped === 'duplicate';
    assert.equal(response.decision, shouldBeBlocked ? 'deny' : 'allow', alert.id);
  }
  const denied = [...outcomes].filter(([, result]) => result.outcome === 'denied').map(([id]) => id).sort();
  // bf-02는 bf-01과 같은 주소라 이미 막혀 있어 새 규칙을 넣지 않고 알림만 남깁니다.
  assert.deepEqual(denied, ['bf-01', 'bf-03', 'bf-04', 'bf-05', 'bf-06', 'bf-07', 'bf-08', 'bf-09', 'bf-10']);
  assert.equal(outcomes.get('bf-02').skipped, 'duplicate');
  for (const id of ['bf-11', 'bf-12', 'bf-13', 'bf-18', 'bf-19']) assert.equal(outcomes.get(id).outcome, 'alerted', id);
  for (let n = 20; n <= 28; n += 1) assert.equal(outcomes.get(`bf-${n}`).outcome, 'recorded', `bf-${n}`);
  assert.equal(JSON.stringify(fixture), before, '경보 원본은 바뀌지 않음');
});

test('deny rules carry an expiry and the alert id, and they stop applying after the expiry', async () => {
  const alert = fixture.alerts.find((item) => item.id === 'bf-01');
  let clock = Date.parse(alert.timestamp);
  const denyList = createDenyList({ now: () => clock });
  const { rule: first } = await handleAlert(alert, { denyList, logFile: await logPath(), now: () => clock });
  assert.equal(first.type, 'deny');
  assert.equal(first.alertId, 'bf-01');
  assert.equal(first.ruleId, `${RULE_ID}.bf-01`);
  assert.equal(Date.parse(first.expiresAt) - Date.parse(first.createdAt), 15 * 60 * 1000);
  const guarded = withBruteForceDeny(async () => ({ decision: 'allow' }), { denyList, addressOf: () => first.address });
  clock = Date.parse(first.expiresAt) - 1;
  assert.equal((await guarded({ requestId: 'r1' })).decision, 'deny');
  clock = Date.parse(first.expiresAt);
  assert.equal((await guarded({ requestId: 'r2' })).decision, 'allow', '만료 시각이 되면 풀림');
  assert.equal(denyList.match(first.address), null);
});

test('the deny response uses exactly the five decision fields and never turns a deny into an allow', async () => {
  let clock = 1_000_000;
  const denyList = createDenyList({ now: () => clock });
  denyList.add(alertWith('a-1', '203.0.113.5'), BLOCK_DECISION);
  const refusing = async (request) => ({ schema: 'aleph.decision.v1', requestId: request.requestId, decision: 'deny', reasonCode: 'starter_not_ready', ruleIds: ['starter.deny'] });
  const guarded = withBruteForceDeny(refusing, { denyList, addressOf: () => '203.0.113.5', reasonCode: 'bruteforce_blocked' });
  const denied = await guarded({ requestId: 'abc' });
  assert.deepEqual(Object.keys(denied).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  assert.deepEqual({ ...denied }, { schema: 'aleph.decision.v1', requestId: 'abc', decision: 'deny', reasonCode: 'bruteforce_blocked', ruleIds: [RULE_ID] });
  // 규칙에 걸리지 않으면 원래 판정기의 답이 그대로 나옵니다(허용으로 바뀌지 않음).
  const passed = await withBruteForceDeny(refusing, { denyList, addressOf: () => '203.0.113.99' })({ requestId: 'xyz' });
  assert.equal(passed.decision, 'deny');
  assert.equal(passed.reasonCode, 'starter_not_ready');
  // 주소를 모르면(기본값) 아무것도 막지 않고, 주소 함수가 던져도 원래 판정기로 넘깁니다.
  const unknown = await withBruteForceDeny(async () => ({ decision: 'allow' }), { denyList })({ requestId: 'q' });
  assert.equal(unknown.decision, 'allow');
  const thrower = await withBruteForceDeny(async () => ({ decision: 'allow' }), { denyList, addressOf: () => { throw new Error('x'); } })({ requestId: 'q' });
  assert.equal(thrower.decision, 'allow');
  assert.throws(() => withBruteForceDeny('not a function', { denyList }), TypeError);
  assert.throws(() => withBruteForceDeny(refusing, {}), TypeError);
});

test('rules are never created for addresses that could belong to normal users', () => {
  const list = createDenyList({ now: () => 5_000_000, protectedAddresses: ['203.0.113.77', ' 2001:DB8::7 '] });
  const skipped = (alert, decision = BLOCK_DECISION) => list.add(alert, decision).skipped;
  for (const internal of ['10.0.0.5', '172.16.4.4', '172.31.255.1', '192.168.1.5', '127.0.0.1', '169.254.1.1', '0.0.0.0', '100.64.0.9', '224.0.0.1', '::1', '::', 'fe80::1', 'fd00::1', '::ffff:a00:1']) {
    assert.equal(skipped(alertWith(`i-${internal}`.slice(0, 20).replace(/[^A-Za-z0-9._-]/gu, '_'), internal)), 'internal_address', internal);
  }
  assert.equal(skipped(alertWith('m-1', '::ffff:10.0.0.1')), 'bad_address', '점이 섞인 IPv6 표기는 주소로 받지 않음');
  assert.equal(skipped(alertWith('p-1', '203.0.113.77')), 'protected_address');
  assert.equal(skipped(alertWith('p-2', '2001:db8::7')), 'protected_address', '대소문자·공백이 달라도 지킴');
  for (const bad of [undefined, null, '', 'not-an-ip', '999.1.1.1', '203.0.113.0/24', '*', '0.0.0.0/0', '203.0.113.5; drop', 42]) {
    assert.equal(skipped(alertWith('b-1', bad)), 'bad_address', String(bad));
  }
  assert.equal(list.active().length, 0);
  assert.equal(list.add(alertWith('ok-1', '172.32.0.1'), BLOCK_DECISION).rule?.address, '172.32.0.1', '172.16~31 밖은 공인 주소');
  assert.ok(list.add(alertWith('ok-2', '198.51.100.9'), BLOCK_DECISION).rule);
});

test('the deny list does not trust a decision that the alert itself contradicts', () => {
  const list = createDenyList({ now: () => 9_000_000 });
  assert.equal(list.add(alertWith('d-1', '203.0.113.1'), { action: 'alert', confidence: 0.6, reason: 'x' }).skipped, 'not_block');
  assert.equal(list.add(alertWith('d-2', '203.0.113.2'), { action: 'record', confidence: 0, reason: 'x' }).skipped, 'not_block');
  assert.equal(list.add(alertWith('d-3', '203.0.113.3'), { action: 'block', confidence: 0.84, reason: 'x' }).skipped, 'not_block', '확신도 0.85 미만');
  for (const confidence of [NaN, Infinity, 1.5, '0.9', undefined, null]) {
    assert.equal(list.add(alertWith('d-4', '203.0.113.4'), { action: 'block', confidence, reason: 'x' }).skipped, 'not_block', String(confidence));
  }
  assert.equal(list.add(alertWith('d-5', '203.0.113.5', { rule: { description: '실패 90건 뒤에 성공했습니다.' } }), BLOCK_DECISION).skipped, 'success_mentioned');
  for (const id of [undefined, '', 'has space', 'new\nline', 'x'.repeat(65), 7]) {
    assert.equal(list.add({ ...alertWith('x', '203.0.113.6'), id }, BLOCK_DECISION).skipped, 'no_alert_id', String(id));
  }
  assert.equal(list.add(null, BLOCK_DECISION).skipped, 'no_alert_id');
  assert.equal(list.add(alertWith('d-6', '203.0.113.7'), null).skipped, 'not_block');
  assert.equal(list.active().length, 0);
});

test('rule count and lifetime are bounded', () => {
  let clock = 1_000;
  const small = createDenyList({ now: () => clock, maxRules: 3 });
  for (let n = 1; n <= 3; n += 1) assert.ok(small.add(alertWith(`l-${n}`, `203.0.113.${n}`), BLOCK_DECISION).rule);
  assert.equal(small.add(alertWith('l-4', '203.0.113.4'), BLOCK_DECISION).skipped, 'rule_limit', '위조 경보가 쏟아져도 상한에서 멈춤');
  assert.equal(small.add(alertWith('l-5', '203.0.113.1'), BLOCK_DECISION).skipped, 'duplicate');
  clock += 16 * 60 * 1000;
  assert.equal(small.active().length, 0, '만료된 규칙은 자리를 비움');
  assert.ok(small.add(alertWith('l-6', '203.0.113.4'), BLOCK_DECISION).rule);

  const ttlOf = (ttlMs) => {
    const rule = createDenyList({ now: () => 0, ttlMs }).add(alertWith('t-1', '203.0.113.1'), BLOCK_DECISION).rule;
    return Date.parse(rule.expiresAt) - Date.parse(rule.createdAt);
  };
  assert.equal(ttlOf(undefined), 15 * 60 * 1000);
  assert.equal(ttlOf(Number.MAX_SAFE_INTEGER), 24 * 60 * 60 * 1000, '영구 차단은 만들지 않음');
  assert.equal(ttlOf(1), 60 * 1000);
  assert.equal(ttlOf(Infinity), 15 * 60 * 1000);
});

test('alerts.log gets one safe line per notification and records nothing for normal events', async () => {
  const run = await replay();
  const lines = (await readFile(run.logFile, 'utf8')).split('\n').filter(Boolean);
  const kinds = lines.map((line) => line.split(' ')[1]);
  assert.equal(kinds.filter((kind) => kind === 'BLOCK').length, 9);
  assert.equal(kinds.filter((kind) => kind === 'ALERT').length, 10);
  assert.equal(lines.length, 19, '기록만 하는 정상 이벤트 9건은 로그에 없음');
  assert.ok(lines.every((line) => /^\d{4}-\d\d-\d\dT[\d:.]+Z (?:BLOCK|ALERT) alert=\S+ action=(?:block|alert) confidence=[\d.]+ /u.test(line)));
  const block = lines.find((line) => line.includes('alert=bf-01 '));
  assert.match(block, /rule=xdr\.bruteforce\.deny\.bf-01 address=203\.0\.113\.10 expires=\d{4}-/u);
  assert.match(lines.find((line) => line.includes('alert=bf-02 ')), /block_skipped=duplicate/u);
  const text = lines.join('\n');
  assert.doesNotMatch(text, /user0\d|같은 주소|비밀번호/u, '계정 이름과 경보 설명은 싣지 않음');
  // 다시 흘리면 같은 파일에 계속 쌓입니다.
  await replay({ logFile: run.logFile });
  assert.equal((await readFile(run.logFile, 'utf8')).split('\n').filter(Boolean).length, 38);
});

test('log lines cannot be forged from alert fields and a failed log write does not undo a block', async () => {
  const logFile = await logPath();
  const list = createDenyList({ now: () => 7_000_000 });
  await respond({ id: 'evil\nBLOCK alert=fake', rule: { description: '실패' }, data: { srcip: '203.0.113.50' } },
    { action: 'alert', confidence: 0.6, reason: '줄\r\n바꿈 "따옴표" \u0000 제어문자' }, { denyList: list, logFile, now: () => 7_000_000 });
  const content = await readFile(logFile, 'utf8');
  assert.equal(content.split('\n').filter(Boolean).length, 1);
  assert.match(content, /alert=- /u);
  assert.doesNotMatch(content, /fake|\u0000/u);

  const missingDir = join(await mkdtemp(join(tmpdir(), 'xdr-respond-')), 'no-such-dir', 'alerts.log');
  const result = await respond(alertWith('w-1', '203.0.113.60'), BLOCK_DECISION, { denyList: list, logFile: missingDir, now: () => 7_000_000 });
  assert.equal(result.outcome, 'denied');
  assert.equal(result.logged, false);
  assert.ok(list.match('203.0.113.60'), '로그를 못 써도 규칙은 들어감');
  await assert.rejects(respond(alertWith('w-2', '203.0.113.61'), BLOCK_DECISION, {}), TypeError);
});

test('decide.mjs stays a pure judge and the decider rules are untouched', () => {
  const decideSource = readFileSync(new URL('../xdr/brute-force/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(decideSource, /respond|alerts\.log|appendFile|denyList|deny list/u);
  const decider = readFileSync(new URL('../src/decider.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(decider, /respond|bruteforce|xdr/u);
  assert.match(decider, /RULE_IDS = Object\.freeze\(\['starter\.deny'\]\)/u);
  // decide()는 여전히 같은 경보에 같은 답을 냅니다.
  assert.deepEqual(decide(fixture.alerts[0]), decide(fixture.alerts[0]));
});
