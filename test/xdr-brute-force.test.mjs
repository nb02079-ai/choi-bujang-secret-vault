import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { isDecision } from '../scripts/xdr-run.mjs';
import { assess, decide } from '../xdr/brute-force/decide.mjs';

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
  const action = (id) => assess(fixture.alerts.find((alert) => alert.id === id)).action;
  for (const id of ['bf-01', 'bf-02', 'bf-04', 'bf-06', 'bf-08', 'bf-10']) assert.equal(action(id), 'block', id);
  for (const id of ['bf-11', 'bf-12', 'bf-13', 'bf-14', 'bf-18']) assert.equal(action(id), 'alert', id);
  for (const id of ['bf-20', 'bf-21', 'bf-22', 'bf-24', 'bf-28']) assert.equal(action(id), 'record', id);
});

test('thresholds include the boundary value itself', () => {
  assert.equal(assess(alertOf({ count: '14' })).action, 'alert');
  assert.equal(assess(alertOf({ count: '15' })).action, 'block');
  assert.equal(assess(alertOf({ count: 15 })).action, 'block', '숫자로 와도 같은 결과');
  assert.equal(assess(alertOf({ count: '2' })).action, 'record');
  assert.equal(assess(alertOf({ count: '3' })).action, 'alert');
  assert.equal(assess(alertOf({ accounts: 'user01,user02,user03,user04' })).action, 'alert');
  assert.equal(assess(alertOf({ accounts: 'user01,user02,user03,user04,user05' })).action, 'block');
  assert.equal(assess(alertOf({ accounts: 'user01,user01,user01,user01,user01' })).action, 'record', '같은 계정을 반복해 적어도 계정 수는 늘지 않음');
  assert.equal(assess(alertOf({ accounts: 'user01,user02' })).action, 'alert');
});

test('block is withheld when a success is mentioned or the address is not usable', () => {
  assert.equal(assess(alertOf({ count: '90' }, '실패 90건 뒤에 성공했습니다.')).action, 'alert');
  assert.equal(assess(alertOf({ count: '90' }, '로그인 실패 90건이 있고 성공은 없습니다.')).action, 'block');
  for (const srcip of [undefined, '', 'not-an-ip', '999.1.1.1', '203.0.113.9; drop', 42, null]) {
    const decision = assess({ rule: { description: 'x' }, data: { srcip, count: '90' } });
    assert.equal(decision.action, 'alert', String(srcip));
  }
  assert.equal(assess({ rule: { description: 'x' }, data: { srcip: '2001:db8::1', count: '90' } }).action, 'block');
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
    const text = JSON.stringify(assess(alert));
    assert.doesNotMatch(text, new RegExp(`${secret}|203\\.0\\.113`, 'u'));
  }
});
