import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { extract, formatRow, readAlerts } from '../xdr/web-injection/read-alerts.mjs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');

test('reader: line count equals alert count, only five fields, fixture untouched', async () => {
  const before = read('../xdr/fixtures/web-injection.json');
  const { alerts, rows, lines } = await readAlerts();
  assert.equal(alerts, 26);
  assert.equal(rows.length, alerts);
  assert.equal(lines.length, alerts);
  assert.equal(read('../xdr/fixtures/web-injection.json'), before);
  assert.deepEqual(Object.keys(rows[0]).sort(), ['description', 'level', 'srcip', 'srcuser', 'timestamp']);
  assert.equal(lines[0], '2026-09-27T09:13:01+09:00 | 203.0.113.10 | - | 12 | 같은 주소에서 SQL 구문을 이어 붙인 요청이 12번 반복됐습니다.', '공격 경보에는 계정이 없어 - 로 채움');
  assert.equal(lines[17], '2026-09-27T09:04:05+09:00 | 192.0.2.70 | user01 | 3 | 자료 목록을 조회했습니다.', '정상 이벤트에는 계정이 있음');
  assert.ok(lines.every((line) => !/[\r\n]/u.test(line) && line.split(' | ').length >= 5));
  const extra = JSON.stringify(extract({ agent: { name: 'PC-AGENT' }, rule: { mitre: ['T1190'] }, data: { url: '/URL-NOT-READ', count: '77', srcuser: 'user01' } }));
  assert.doesNotMatch(extra, /PC-AGENT|T1190|URL-NOT-READ|77/u, '다섯 필드 밖의 내용은 읽어 내지 않음');
  assert.match(extra, /user01/u);
});

test('reader: secret-looking values are masked in every extracted field', () => {
  const samples = ['sb_secret_abcdefghijkl', 'sb_publishable_abcdefghij1234', 'Bearer abcdefghijklmnop', 'eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.abcdEFGH',
    'sk-abcdefghijklmnopqrstuv', 'password=hunter2', 'token: abc123', 'student@example.test', '/cb?access_token=abc123secret&x=1',
    '/a?key=zzz999&b=2', '/a?session=s3ss10n;sig=deadbeef', '-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----'];
  for (const secret of samples) {
    const row = extract({ timestamp: `t ${secret}`, rule: { level: 5, description: `앞 ${secret} 뒤` }, data: { srcip: `ip ${secret}`, srcuser: secret } });
    const text = JSON.stringify(row);
    assert.match(text, /\[가림\]/u, secret);
    assert.doesNotMatch(text, /abcdefghijkl|hunter2|abc123|student@|MIIEvQ|PRIVATE KEY|eyJhbGci|zzz999|s3ss10n|deadbeef/u, secret);
    assert.match(row.description, /^앞 .* 뒤$/u, '주변 문장은 남김');
  }
  assert.equal(extract({ rule: { description: '검색어 week3 으로 조회했습니다.' } }).description, '검색어 week3 으로 조회했습니다.', '비밀이 아닌 문장은 그대로');
  assert.equal(formatRow({ timestamp: null, srcip: '1', srcuser: null, level: '3', description: 'd' }), '- | 1 | - | 3 | d');
});

test('reader: odd alerts still produce one line each and a wrong fixture is rejected', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'xdr-web-'));
  const file = join(dir, 'w.json');
  await writeFile(file, JSON.stringify({ schema: 'aleph.xdr.fixture.v1', moduleKey: 'web-injection', alerts: [{}, null, { data: { srcuser: 5 } }, { rule: { description: 'a\nb' } }] }), 'utf8');
  const { lines, rows } = await readAlerts(file);
  assert.equal(lines.length, 4);
  assert.equal(lines[0], '- | - | - | - | -');
  assert.equal(rows[2].srcuser, '5');
  assert.equal(rows[3].description, 'a b', '줄바꿈은 한 줄로 합침');
  assert.ok(lines.every((line) => !/[\r\n]/u.test(line)));
  await writeFile(file, JSON.stringify({ schema: 'aleph.xdr.fixture.v1', moduleKey: 'privilege', alerts: [] }), 'utf8');
  await assert.rejects(readAlerts(file), /web-injection/u);
});

test('reader does not import decide.mjs', () => {
  assert.doesNotMatch(read('../xdr/web-injection/read-alerts.mjs'), /from\s+['"][^'"]*decide/u);
});
