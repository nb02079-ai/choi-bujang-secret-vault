import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { extract, formatRow, readAlerts } from '../xdr/brute-force/read-alerts.mjs';

const fixturePath = new URL('../xdr/fixtures/brute-force.json', import.meta.url);

async function withFixture(alerts, run) {
  const dir = await mkdtemp(join(tmpdir(), 'xdr-read-'));
  const file = join(dir, 'brute-force.json');
  await writeFile(file, JSON.stringify({ schema: 'aleph.xdr.fixture.v1', moduleKey: 'brute-force', alerts }), 'utf8');
  return run(file);
}

test('line count equals alert count and the fixture file is left untouched', async () => {
  const before = await readFile(fixturePath, 'utf8');
  const { alerts, rows, lines } = await readAlerts();
  assert.equal(alerts, 28);
  assert.equal(rows.length, alerts);
  assert.equal(lines.length, alerts);
  assert.equal(await readFile(fixturePath, 'utf8'), before);
  assert.deepEqual(Object.keys(rows[0]).sort(), ['description', 'level', 'srcip', 'srcuser', 'timestamp']);
  assert.equal(lines[0], '2026-09-27T09:12:01+09:00 | 203.0.113.10 | user01 | 12 | 같은 주소에서 2분 안에 로그인 실패 48건이 쌓였습니다.');
  assert.ok(lines.every((line) => !line.includes('\n') && line.split(' | ').length >= 5));
});

test('only the five fields are extracted; other alert content is never read out', () => {
  const row = extract({ id: 'x', timestamp: 't', agent: { name: 'PC-SECRET-AGENT' }, full_log: 'LOG-BODY',
    rule: { level: 9, description: 'd', mitre: ['T1110'] }, data: { srcip: '203.0.113.1', srcuser: 'user01', count: '5', accounts: 'a,b' } });
  assert.deepEqual(row, { timestamp: 't', srcip: '203.0.113.1', srcuser: 'user01', level: '9', description: 'd' });
  assert.doesNotMatch(JSON.stringify(row), /PC-SECRET-AGENT|LOG-BODY|T1110|a,b/u);
});

test('secret-looking values are masked in every extracted field', () => {
  const samples = ['sb_secret_abcdefghijkl', 'sb_publishable_abcdefghij1234', 'Bearer abcdefghijklmnop',
    'eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.abcdEFGH', 'sk-abcdefghijklmnopqrstuv', 'password=hunter2', 'token: abc123',
    'student@example.test', '-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----'];
  for (const secret of samples) {
    const row = extract({ timestamp: `t ${secret}`, rule: { level: 5, description: `앞 ${secret} 뒤` },
      data: { srcip: `ip ${secret}`, srcuser: secret } });
    const text = JSON.stringify(row);
    assert.match(text, /\[가림\]/u, secret);
    assert.doesNotMatch(text, /abcdefghijkl|hunter2|abc123|student@|MIIEvQ|PRIVATE KEY|eyJhbGci/u, secret);
    assert.match(row.description, /^앞 .* 뒤$/u, '주변 문장은 남김');
  }
});

test('missing or odd fields still produce exactly one line each', async () => {
  const alerts = [{}, null, { data: null }, { rule: { level: {}, description: ['a'] }, data: { srcip: 5 } },
    { timestamp: 'a\nb\r\nc', rule: { description: 'x'.repeat(500) }, data: { srcuser: '   ' } }];
  await withFixture(alerts, async (file) => {
    const { alerts: count, lines, rows } = await readAlerts(file);
    assert.equal(count, 5);
    assert.equal(lines.length, 5);
    assert.equal(lines[0], '- | - | - | - | -');
    assert.equal(rows[3].srcip, '5');
    assert.equal(rows[3].level, null);
    assert.equal(rows[4].timestamp, 'a b c', '줄바꿈은 한 줄로 합침');
    assert.equal(rows[4].srcuser, null);
    assert.ok(rows[4].description.length <= 201);
    assert.ok(lines.every((line) => !/[\r\n]/u.test(line)));
  });
});

test('a file that is not a brute-force fixture is rejected', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'xdr-read-'));
  const file = join(dir, 'x.json');
  await writeFile(file, JSON.stringify({ schema: 'aleph.xdr.fixture.v1', moduleKey: 'privilege', alerts: [] }), 'utf8');
  await assert.rejects(readAlerts(file), /brute-force/u);
  assert.equal(formatRow({ timestamp: null, srcip: '1', srcuser: null, level: '3', description: 'd' }), '- | 1 | - | 3 | d');
});

test('the read module and decide.mjs do not import each other', async () => {
  const decide = await readFile(new URL('../xdr/brute-force/decide.mjs', import.meta.url), 'utf8');
  const reader = await readFile(new URL('../xdr/brute-force/read-alerts.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(decide, /read-alerts/u);
  assert.doesNotMatch(reader, /from\s+['"][^'"]*decide/u);
});
