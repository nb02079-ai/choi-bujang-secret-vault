import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { decide } from '../xdr/brute-force/decide.mjs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const doc = JSON.parse(read('../xdr/brute-force/patterns.json'));
const fixture = JSON.parse(read('../xdr/fixtures/brute-force.json'));
const decideSource = read('../xdr/brute-force/decide.mjs');
const oneLine = (text) => typeof text === 'string' && text.trim().length >= 10 && !/[\r\n]/u.test(text);

// decide.mjs 맨 위 PATTERNS-BEGIN ~ PATTERNS-END 사이의 JSON 모양 상수를 그대로 읽습니다.
function patternsInDecide() {
  const body = /\/\/ PATTERNS-BEGIN\r?\n([\s\S]*?)\r?\n\/\/ PATTERNS-END/u.exec(decideSource)?.[1];
  assert.ok(body, 'PATTERNS 표시 구간이 있어야 함');
  const literal = body.replace(/^const PATTERNS = /u, '').replace(/;\s*$/u, '');
  return JSON.parse(literal);
}

test('every pattern has a name, a condition and exactly one line of evidence with a MITRE source', () => {
  assert.equal(doc.basis.technique, 'T1110');
  assert.ok(doc.patterns.length >= 2);
  const names = new Set();
  for (const pattern of doc.patterns) {
    assert.match(pattern.name, /^[a-z][a-z0-9_]{2,60}$/u);
    assert.ok(!names.has(pattern.name), `중복 이름 ${pattern.name}`);
    names.add(pattern.name);
    assert.match(pattern.technique, /^T1110(\.00[1-4])?$/u, pattern.name);
    assert.ok(oneLine(pattern.condition), `${pattern.name} condition`);
    assert.ok(oneLine(pattern.evidence), `${pattern.name} evidence는 한 줄이어야 함`);
    assert.ok(pattern.evidence.includes(pattern.technique), `${pattern.name} 근거에 기법 번호가 있어야 함`);
    assert.ok(pattern.source.startsWith('https://attack.mitre.org/techniques/T1110'), pattern.name);
    assert.ok(pattern.source.includes(pattern.technique.replace('.', '/')), `${pattern.name} 출처가 기법과 맞아야 함`);
    assert.deepEqual(Object.keys(pattern).sort(), ['condition', 'evidence', 'fields', 'name', 'source', 'technique', 'thresholds']);
  }
});

test('the two requested signals are present and no pattern lacks a basis', () => {
  const byName = Object.fromEntries(doc.patterns.map((pattern) => [pattern.name, pattern]));
  assert.equal(byName.rapid_failures_same_source.technique, 'T1110.001');
  assert.equal(byName.password_spraying_many_accounts.technique, 'T1110.003');
  assert.ok(doc.patterns.every((pattern) => oneLine(pattern.evidence) && pattern.source));
});

test('the constants at the top of decide.mjs are exactly the patterns in patterns.json', () => {
  assert.deepEqual(patternsInDecide(), doc.patterns);
});

test('the thresholds in the patterns are what decide() really uses', () => {
  const byName = Object.fromEntries(doc.patterns.map((pattern) => [pattern.name, pattern]));
  const failures = byName.rapid_failures_same_source.thresholds.failures;
  const accounts = byName.password_spraying_many_accounts.thresholds.accounts;
  const alertOf = (data) => ({ rule: { description: '실패' }, data: { srcip: '203.0.113.9', srcuser: 'user01', ...data } });
  assert.equal(decide(alertOf({ count: String(failures - 1) })).action, 'alert');
  assert.equal(decide(alertOf({ count: String(failures) })).action, 'block');
  const names = (n) => Array.from({ length: n }, (_, i) => `user${i + 1}`).join(',');
  assert.equal(decide(alertOf({ accounts: names(accounts - 1) })).action, 'alert');
  assert.equal(decide(alertOf({ accounts: names(accounts) })).action, 'block');
  assert.ok(byName.rapid_failures_same_source.condition.includes(String(failures)));
  assert.ok(byName.password_spraying_many_accounts.condition.includes(String(accounts)));
});

test('every field a pattern reads exists in the fixture alerts', () => {
  const has = (alert, path) => path.split('.').reduce((node, key) => (node && typeof node === 'object' ? node[key] : undefined), alert) !== undefined;
  for (const pattern of doc.patterns) {
    for (const field of pattern.fields) {
      assert.ok(fixture.alerts.some((alert) => has(alert, field)), `${pattern.name}: ${field}`);
    }
  }
});

test('techniques left out are named with a reason and are not patterns', () => {
  const used = new Set(doc.patterns.map((pattern) => pattern.technique));
  for (const skipped of doc.notIncluded) {
    assert.ok(!used.has(skipped.technique), skipped.technique);
    assert.ok(oneLine(skipped.reason), skipped.technique);
  }
});
