import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const doc = JSON.parse(read('../xdr/web-injection/patterns.json'));
const fixture = JSON.parse(read('../xdr/fixtures/web-injection.json'));
const byName = Object.fromEntries(doc.patterns.map((pattern) => [pattern.name, pattern]));
const oneLine = (text) => typeof text === 'string' && text.trim().length >= 10 && !/[\r\n]/u.test(text);

test('patterns: each has a name, a condition and exactly one line of evidence grounded in T1190', () => {
  assert.equal(doc.basis.technique, 'T1190');
  assert.equal(doc.basis.url, 'https://attack.mitre.org/techniques/T1190/');
  const names = new Set();
  for (const pattern of doc.patterns) {
    assert.match(pattern.name, /^[a-z][a-z0-9_]{2,60}$/u);
    assert.ok(!names.has(pattern.name), `중복 이름 ${pattern.name}`);
    names.add(pattern.name);
    assert.equal(pattern.technique, 'T1190');
    assert.ok(oneLine(pattern.condition), `${pattern.name} condition`);
    assert.ok(oneLine(pattern.evidence), `${pattern.name} evidence는 한 줄이어야 함`);
    assert.ok(pattern.evidence.includes('T1190'), `${pattern.name} 근거에 T1190이 있어야 함`);
    assert.equal(pattern.source, doc.basis.url, `${pattern.name} 근거 주소는 T1190`);
    assert.ok(pattern.weakness === null || /^CWE-\d+$/u.test(pattern.weakness), pattern.name);
    if (pattern.weakness) {
      assert.ok(pattern.evidence.includes(pattern.weakness), `${pattern.name} 근거에 ${pattern.weakness}가 있어야 함`);
      assert.equal(pattern.weaknessSource, `https://cwe.mitre.org/data/definitions/${pattern.weakness.slice(4)}.html`, pattern.name);
    } else {
      assert.equal(pattern.weaknessSource, null, pattern.name);
    }
    assert.equal(typeof pattern.alertOnly, 'boolean');
    assert.deepEqual(Object.keys(pattern).sort(), ['alertOnly', 'condition', 'evidence', 'fields', 'name', 'source', 'technique', 'thresholds', 'weakness', 'weaknessSource']);
  }
});

test('patterns: the three requested signals are present and can block, extra ones only alert', () => {
  assert.match(byName.sql_injection_repeated.condition, /SQL 구문/u);
  assert.match(byName.script_injection_repeated.condition, /스크립트 태그/u);
  assert.match(byName.path_traversal_repeated.condition, /\.\.\//u);
  for (const name of ['sql_injection_repeated', 'script_injection_repeated', 'path_traversal_repeated']) {
    assert.equal(byName[name].alertOnly, false, name);
    assert.equal(byName[name].thresholds.repeats, 5, name);
  }
  assert.equal(byName.command_separator_repeated.alertOnly, true, '지시한 신호 밖의 추가 패턴은 알림만');
  assert.equal(byName.single_injection_like_attempt.alertOnly, true);
  assert.match(byName.command_separator_repeated.condition, /추가 패턴/u);
});

test('patterns: every field a pattern reads exists in the fixture alerts', () => {
  const has = (alert, path) => path.split('.').reduce((node, key) => (node && typeof node === 'object' ? node[key] : undefined), alert) !== undefined;
  for (const pattern of doc.patterns) {
    for (const field of pattern.fields) assert.ok(fixture.alerts.some((alert) => has(alert, field)), `${pattern.name}: ${field}`);
  }
});
