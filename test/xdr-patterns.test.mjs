import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { ALERT_ACCOUNTS, ALERT_FAILURES, BLOCK_ACCOUNTS, BLOCK_FAILURES } from '../xdr/brute-force/decide.mjs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const doc = JSON.parse(read('../xdr/brute-force/patterns.json'));
const fixture = JSON.parse(read('../xdr/fixtures/brute-force.json'));
const oneLine = (text) => typeof text === 'string' && text.trim().length >= 10 && !/[\r\n]/u.test(text);

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

test('thresholds match the constants decide.mjs actually uses', () => {
  const byName = Object.fromEntries(doc.patterns.map((pattern) => [pattern.name, pattern]));
  assert.equal(byName.rapid_failures_same_source.thresholds.failures, BLOCK_FAILURES);
  assert.equal(byName.password_spraying_many_accounts.thresholds.accounts, BLOCK_ACCOUNTS);
  assert.ok(BLOCK_FAILURES > ALERT_FAILURES && BLOCK_ACCOUNTS > ALERT_ACCOUNTS);
  assert.ok(byName.rapid_failures_same_source.condition.includes(String(BLOCK_FAILURES)));
  assert.ok(byName.password_spraying_many_accounts.condition.includes(String(BLOCK_ACCOUNTS)));
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

test('decide.mjs does not read patterns.json', () => {
  assert.doesNotMatch(read('../xdr/brute-force/decide.mjs'), /patterns\.json/u);
});
