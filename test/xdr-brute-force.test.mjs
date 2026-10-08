import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { isDecision } from '../scripts/xdr-run.mjs';
import { decide } from '../xdr/brute-force/decide.mjs';

const fixture = JSON.parse(readFileSync(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
const alertOf = (data, description = '로그인 실패가 쌓였습니다.') => ({ id: 't', rule: { description }, data: { srcip: '203.0.113.9', srcuser: 'user01', ...data } });

test('every fixture alert gets a valid decision and the fixture is not modified', async () => {
  const before = JSON.stringify(fixture);
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) {
    const decision = await decide(alert);
    assert.ok(isDecision(decision), alert.id);
    assert.deepEqual(Object.keys(decision).sort(), ['action', 'confidence', 'reason']);
    counts[decision.action] += 1;
  }
  assert.equal(JSON.stringify(fixture), before);
  assert.deepEqual(counts, { block: 10, alert: 9, record: 9 });
});

test('clear attacks are blocked, ambiguous tries are alerts, normal events are only recorded', () => {
  const action = (id) => decide(fixture.alerts.find((alert) => alert.id === id)).action;
  for (const id of ['bf-01', 'bf-02', 'bf-04', 'bf-06', 'bf-08', 'bf-10']) assert.equal(action(id), 'block', id);
  for (const id of ['bf-11', 'bf-12', 'bf-13', 'bf-14', 'bf-18']) assert.equal(action(id), 'alert', id);
  for (const id of ['bf-20', 'bf-21', 'bf-22', 'bf-24', 'bf-28']) assert.equal(action(id), 'record', id);
});

test('thresholds include the boundary value itself', () => {
  assert.equal(decide(alertOf({ count: '14' })).action, 'alert');
  assert.equal(decide(alertOf({ count: '15' })).action, 'block');
  assert.equal(decide(alertOf({ count: 15 })).action, 'block', '숫자로 와도 같은 결과');
  assert.equal(decide(alertOf({ count: '2' })).action, 'record');
  assert.equal(decide(alertOf({ count: '3' })).action, 'alert');
  assert.equal(decide(alertOf({ accounts: 'user01,user02,user03,user04' })).action, 'alert');
  assert.equal(decide(alertOf({ accounts: 'user01,user02,user03,user04,user05' })).action, 'block');
  assert.equal(decide(alertOf({ accounts: 'user01,user01,user01,user01,user01' })).action, 'record', '같은 계정을 반복해 적어도 계정 수는 늘지 않음');
  assert.equal(decide(alertOf({ accounts: 'user01,user02' })).action, 'alert');
});

test('block is withheld when a success is mentioned or the address is not usable', () => {
  assert.equal(decide(alertOf({ count: '90' }, '실패 90건 뒤에 성공했습니다.')).action, 'alert');
  assert.equal(decide(alertOf({ count: '90' }, '로그인 실패 90건이 있고 성공은 없습니다.')).action, 'block');
  for (const srcip of [undefined, '', 'not-an-ip', '999.1.1.1', '203.0.113.9; drop', 42, null]) {
    const decision = decide({ rule: { description: 'x' }, data: { srcip, count: '90' } });
    assert.equal(decision.action, 'alert', String(srcip));
  }
  assert.equal(decide({ rule: { description: 'x' }, data: { srcip: '2001:db8::1', count: '90' } }).action, 'block');
});

test('malformed alerts never throw, never block and are only recorded', async () => {
  for (const bad of [undefined, null, 'text', 7, [], {}, { data: null }, { data: [] }, { data: { count: -1 } },
    { data: { count: 'abc' } }, { data: { count: 1.5 } }, { data: { count: '9'.repeat(30) } }, { data: { count: {} } },
    { data: { accounts: 5 } }, { data: { accounts: 'user01,,user02' } }, { data: { accounts: 'a'.repeat(100) } },
    { data: { accounts: Array.from({ length: 200 }, (_, i) => `u${i}`).join(',') } }]) {
    const decision = await decide(bad);
    assert.ok(isDecision(decision), JSON.stringify(bad)?.slice(0, 40));
    assert.equal(decision.action, 'record', JSON.stringify(bad)?.slice(0, 40));
  }
});

test('reasons never echo alert text, accounts or addresses', () => {
  const secret = 'user-secret-name';
  for (const alert of [alertOf({ count: '90', srcuser: secret }), alertOf({ count: '4', srcuser: secret }), alertOf({ count: '0', srcuser: secret })]) {
    const text = JSON.stringify(decide(alert));
    assert.doesNotMatch(text, new RegExp(`${secret}|203\\.0\\.113`, 'u'));
  }
});

const source = readFileSync(new URL('../xdr/brute-force/decide.mjs', import.meta.url), 'utf8');
const code = source.split(/\r?\n/u).filter((line) => !/^\s*\/\//u.test(line)).join('\n');

test('decide.mjs stands alone: no import, no file, no network, no process access', () => {
  assert.doesNotMatch(code, /^\s*import\b/mu);
  assert.doesNotMatch(code, /\bimport\s*\(/u);
  assert.doesNotMatch(code, /\brequire\s*\(/u);
  assert.doesNotMatch(code, /\bfrom\s+['"]/u);
  assert.doesNotMatch(code, /\b(?:fetch|XMLHttpRequest|WebSocket|readFile|writeFile|readFileSync|writeFileSync|createReadStream|process|globalThis|eval|Function)\b/u);
  assert.doesNotMatch(code, /node:|https?:\/\/(?!attack\.mitre\.org)/u);
});

test('decide is the only export and answers synchronously with exactly three fields', async () => {
  const module = await import('../xdr/brute-force/decide.mjs');
  assert.deepEqual(Object.keys(module), ['decide']);
  const decision = decide(fixture.alerts[0]);
  assert.equal(typeof decision.then, 'undefined', '약속(Promise)이 아니라 바로 답함');
  assert.deepEqual(Object.keys(decision).sort(), ['action', 'confidence', 'reason']);
});

test('action follows confidence: 0.85 and above block, 0.5 and above alert, below that record', () => {
  const seen = new Set();
  for (const alert of fixture.alerts) {
    const { action, confidence } = decide(alert);
    assert.ok(Number.isFinite(confidence) && confidence >= 0 && confidence <= 1, alert.id);
    assert.equal(action, confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', alert.id);
    seen.add(action);
  }
  assert.deepEqual([...seen].sort(), ['alert', 'block', 'record']);
  assert.equal(decide(alertOf({ count: '15' })).confidence, 0.85);
  assert.equal(decide(alertOf({ count: '3' })).confidence, 0.5);
  assert.ok(decide(alertOf({ count: '14' })).confidence < 0.85);
  assert.ok(decide(alertOf({ count: '2' })).confidence < 0.5);
  assert.ok(decide(alertOf({ count: '30' })).confidence > decide(alertOf({ count: '15' })).confidence, '더 뚜렷할수록 확신도가 큼');
  assert.ok(decide(alertOf({ count: '1000' })).confidence <= 0.95);
});

test('reason is one line and names the pattern it matched', () => {
  const names = ['rapid_failures_same_source', 'password_spraying_many_accounts', 'failures_then_success'];
  const block = decide(alertOf({ count: '90' }));
  assert.match(block.reason, /rapid_failures_same_source/u);
  assert.match(decide(alertOf({ accounts: 'user01,user02,user03,user04,user05,user06' })).reason, /password_spraying_many_accounts/u);
  const mixed = decide(alertOf({ count: '90' }, '실패 90건 뒤에 성공했습니다.'));
  assert.match(mixed.reason, /rapid_failures_same_source \+ failures_then_success/u);
  assert.equal(mixed.action, 'alert');
  assert.ok(mixed.confidence < 0.85);
  for (const alert of fixture.alerts) {
    const { action, reason } = decide(alert);
    assert.ok(!/[\r\n]/u.test(reason) && reason.length > 5, alert.id);
    if (action !== 'record') assert.ok(names.some((name) => reason.includes(name)), alert.id);
  }
});
