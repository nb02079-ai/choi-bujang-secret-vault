import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { isDecision } from '../scripts/xdr-run.mjs';
import { decide } from '../xdr/web-injection/decide.mjs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const fixture = JSON.parse(read('../xdr/fixtures/web-injection.json'));
const doc = JSON.parse(read('../xdr/web-injection/patterns.json'));
const decideSource = read('../xdr/web-injection/decide.mjs');
const alertOf = (url, count, extra = {}) => ({ id: 't-1', rule: { level: 10, description: '시험' }, data: { srcip: '203.0.113.9', url, count: String(count) }, ...extra });
const action = (id) => decide(fixture.alerts.find((alert) => alert.id === id)).action;

test('decide.mjs does not use the reader', () => {
  assert.doesNotMatch(decideSource, /read-alerts/u);
});

test('patterns: constants in decide.mjs equal patterns.json and the thresholds are what decide() uses', () => {
  const body = /\/\/ PATTERNS-BEGIN\r?\n([\s\S]*?)\r?\n\/\/ PATTERNS-END/u.exec(decideSource)?.[1];
  assert.ok(body);
  assert.deepEqual(JSON.parse(body.replace(/^const PATTERNS = /u, '').replace(/;\s*$/u, '')), doc.patterns);
  const repeats = doc.patterns.find((pattern) => pattern.name === 'sql_injection_repeated').thresholds.repeats;
  assert.equal(decide(alertOf('/n?q=doc-sql-x', repeats - 1)).action, 'alert');
  assert.equal(decide(alertOf('/n?q=doc-sql-x', repeats)).action, 'block');
});

// ---- 3/5 판단 ----
test('decide: clear SQL, script and ../ repeats are blocked, the rest is alerted or only recorded', async () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) {
    const decision = await decide(alert);
    assert.ok(isDecision(decision), alert.id);
    assert.deepEqual(Object.keys(decision).sort(), ['action', 'confidence', 'reason']);
    assert.equal(decision.action, decision.confidence >= 0.85 ? 'block' : decision.confidence >= 0.5 ? 'alert' : 'record', alert.id);
    counts[decision.action] += 1;
  }
  assert.deepEqual(counts, { block: 8, alert: 4, record: 14 });
  for (const id of ['wi-01', 'wi-02', 'wi-03', 'wi-04', 'wi-05', 'wi-06', 'wi-07', 'wi-08']) assert.equal(action(id), 'block', id);
    for (const id of ['wi-09', 'wi-15', 'wi-16', 'wi-17']) assert.equal(action(id), 'alert', id);
  for (const id of ['wi-10', 'wi-11', 'wi-12', 'wi-13', 'wi-14']) assert.equal(action(id), 'record', `${id} 수업 단어만 있는 평범한 요청`);
  for (let n = 18; n <= 26; n += 1) assert.equal(action(`wi-${n}`), 'record', `wi-${n}`);
});

test('decide: real attack shapes are recognised, plain words are not, encoding does not hide them', () => {
  const blocked = ["/n?q=' OR '1'='1", '/s?q=<script>alert(1)</script>', '/s?q=%3Cscript%3Ealert(1)%3C/script%3E', '/s?q=%253Cscript%253E',
    '/n?id=1 UNION SELECT user FROM t', '/n?id=1; DROP TABLE notes', '/s?q=<img src=x onerror=alert(1)>', '/s?q=javascript:alert(1)', '/n?q=select * from users'];
  for (const url of blocked) assert.equal(decide(alertOf(url, 8)).action, 'block', url);
  for (const url of blocked) assert.equal(decide(alertOf(url, 1)).action, 'alert', `${url} 한 번뿐이면 알림만`);
  for (const url of ['/search?q=select-course', '/search?q=script-class', '/search?q=sql-class-notice', '/files?path=up-notes', '/notes?q=week3',
    '/search?q=%ZZ', '/api/notes/demo']) {
    assert.equal(decide(alertOf(url, 50)).action, 'record', url);
  }
  assert.equal(decide(alertOf('/files?path=../../etc/passwd', 50)).action, 'block', '../ 가 같은 주소에서 반복되면 막음');
  assert.equal(decide(alertOf('/files?path=../../etc/passwd', 4)).action, 'alert', '반복 기준 미만이면 알림까지');
  assert.equal(decide(alertOf('/files?path=..%2f..%2fx', 50)).action, 'block', '인코딩해도 찾음');
  assert.equal(decide(alertOf('/n?q=a;cat /x', 50)).action, 'block', '명령 구분자도 반복되면 막음');
  assert.equal(decide(alertOf('/n?q=a;cat /x', 4)).action, 'alert', '반복 기준 미만이면 알림까지');
});

test('decide: boundary values, mixed markers and the confidence ladder', () => {
  assert.equal(decide(alertOf('/n?q=doc-sql-x', 4)).action, 'alert');
  assert.equal(decide(alertOf('/n?q=doc-sql-x', 5)).action, 'block');
  assert.equal(decide(alertOf('/n?q=doc-sql-x', 5)).confidence, 0.85);
  assert.ok(decide(alertOf('/n?q=doc-sql-x', 4)).confidence < 0.85);
  assert.equal(decide(alertOf('/n?q=doc-sql-x', 1)).confidence, 0.5);
  assert.ok(decide(alertOf('/n?q=doc-sql-x', 10)).confidence > decide(alertOf('/n?q=doc-sql-x', 5)).confidence);
  assert.ok(decide(alertOf('/n?q=doc-sql-x', 1_000_000)).confidence <= 0.95);
  assert.equal(decide(alertOf('/n?q=doc-sql-x', 0)).action, 'record', '건수 0은 요청이 없었다는 뜻');
  const mixed = decide(alertOf('/s?q=doc-mixed-marker', 15));
  assert.equal(mixed.action, 'block');
  assert.match(mixed.reason, /sql_injection_repeated/u);
  assert.match(mixed.reason, /script_injection_repeated/u);
  const noCount = decide({ id: 'n', rule: { description: 'd' }, data: { srcip: '203.0.113.9', url: '/n?q=doc-sql-x' } });
  assert.equal(noCount.action, 'alert', '건수가 없으면 요청 한 번으로 봄');
  assert.equal(decide(alertOf('/search?q=hello', 9, { rule: { description: '따옴표가 한 번 들어 있습니다.' } })).action, 'alert', '설명이 말하는 한 번뿐인 의심 표기');
  assert.equal(decide(alertOf('/search?q=hello', 9, { rule: { description: '삽입 표식은 아닙니다. 공격 표기는 없습니다.' } })).action, 'record', '부정문은 의심 표기로 읽지 않음');
});

test('decide: never blocks without a usable address and never throws on odd alerts', async () => {
  for (const srcip of [undefined, null, '', 'not-an-ip', '999.1.1.1', '203.0.113.5; drop', 7]) {
    const decision = decide({ id: 'a', rule: { description: 'd' }, data: { srcip, url: '/n?q=doc-sql-x', count: '20' } });
    assert.equal(decision.action, 'alert', String(srcip));
    assert.ok(decision.confidence < 0.85);
  }
  assert.equal(decide({ id: 'a', rule: { description: 'd' }, data: { srcip: '2001:db8::1', url: '/n?q=doc-sql-x', count: '20' } }).action, 'block');
  for (const bad of [undefined, null, 'text', 7, [], {}, { data: null }, { data: [] }, { data: { count: -1, url: '/a' } }, { data: { count: 'x', url: '/a' } },
    { data: { count: 1.5 } }, { data: { count: '9'.repeat(30) } }, { data: { count: {}, url: '/a' } }, { data: { url: 5 } }, { data: { url: {} } },
    { data: { url: 'a'.repeat(5000), count: '9' } }, { data: { url: ['/a'], count: '9' } }]) {
    const decision = await decide(bad);
    assert.ok(isDecision(decision), JSON.stringify(bad)?.slice(0, 40));
    assert.equal(decision.action, 'record', JSON.stringify(bad)?.slice(0, 40));
  }
});

test('decide: reasons name the matching pattern in one line and never echo alert text', () => {
  const names = doc.patterns.map((pattern) => pattern.name);
  for (const alert of fixture.alerts) {
    const { action: kind, reason } = decide(alert);
    assert.ok(!/[\r\n]/u.test(reason) && reason.length > 5, alert.id);
    if (kind !== 'record') assert.ok(names.some((name) => reason.includes(name)), alert.id);
  }
  const text = JSON.stringify(decide(alertOf('/n?q=doc-sql-secretword', 9, { rule: { description: 'ECHO-ME' }, data: { srcip: '203.0.113.9', url: '/n?q=doc-sql-secretword', count: '9', srcuser: 'user-xyz' } })));
  assert.doesNotMatch(text, /secretword|ECHO-ME|user-xyz|203\.0\.113/u);
});

test('decide.mjs stands alone: no import, no file, no network, a single synchronous export', async () => {
  const code = decideSource.split(/\r?\n/u).filter((line) => !/^\s*\/\//u.test(line)).join('\n');
  assert.doesNotMatch(code, /^\s*import\b|\bimport\s*\(|\brequire\s*\(|\bfrom\s+['"]/mu);
  assert.doesNotMatch(code, /\b(?:fetch|XMLHttpRequest|WebSocket|readFile|writeFile|readFileSync|writeFileSync|process|globalThis|eval|Function)\b/u);
  assert.doesNotMatch(code, /node:|https?:\/\/(?!attack\.mitre\.org|cwe\.mitre\.org)/u);
  assert.deepEqual(Object.keys(await import('../xdr/web-injection/decide.mjs')), ['decide']);
  assert.equal(typeof decide(fixture.alerts[0]).then, 'undefined');
  assert.deepEqual(decide(fixture.alerts[0]), decide(fixture.alerts[0]));
  assert.doesNotMatch(decideSource, /respond|alerts\.log|appendFile|denyList/u);
});
