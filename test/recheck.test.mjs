import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ATTACK_TOTAL, renderReport, runRecheck, summarize } from '../src/recheck.mjs';
import { UsageError, exitCodeFor, parseArgs } from '../scripts/recheck.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const FIXED = Date.parse('2026-10-14T00:00:00.000Z');
const clock = () => { let tick = 0; return () => new Date(FIXED + (tick += 1) * 1000); };

let cached;
const local = async () => { cached ??= await runRecheck({ now: clock() }); return cached; };

test('실측한 행에는 실제 결과, 요청 ID, 확인 시각, 출처가 모두 있고 일치한다', async () => {
  const { rows } = await local();
  const measured = rows.filter((row) => row.result !== 'not_run');
  assert.ok(measured.length >= 45, `실측 ${measured.length}건`);
  for (const row of measured) {
    const label = `${row.step}단계 ${row.title}`;
    assert.equal(row.result, 'match', `${label}: 기대 ${row.expected} / 실제 ${row.actual}`);
    assert.equal(typeof row.actual, 'string', label);
    assert.ok(row.actual.length > 0, label);
    assert.notEqual(row.source, 'none', label);
    assert.match(row.checkedAt, /^2026-10-14T00:\d\d:\d\d\.000Z$/u, label);
    assert.ok(UUID.test(row.requestId) || row.requestId === '-(파일·함수 호출)', `${label}: ${row.requestId}`);
  }
  // 함수를 호출한 서버 요청과 판정 요청은 모두 고유한 요청 ID를 갖는다
  const ids = measured.map((row) => row.requestId).filter((id) => UUID.test(id));
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(ids.length >= 40);
});

test('2~11단계마다 실측한 정상 요청과 실측한 금지 요청이 모두 있고 모두 일치한다', async () => {
  const { summary, rows } = await local();
  for (let step = 2; step <= 11; step += 1) {
    const entry = summary.steps[step];
    assert.ok(entry.normalMeasured >= 1, `${step}단계 정상 실측`);
    assert.ok(entry.forbiddenMeasured >= 1, `${step}단계 금지 실측`);
    assert.equal(entry.mismatch, 0, `${step}단계 불일치`);
  }
  assert.ok(summary.steps[1].normalMeasured >= 1, '1단계 정상 실측');
  assert.equal(summary.steps[1].forbiddenMeasured, 0, '1단계에는 금지 요청이 없다');
  assert.equal(summary.mismatch, 0);
  // 금지 요청의 거부는 응답 코드만이 아니라 저장소 변화 없음까지 실측했다
  const guarded = rows.filter((row) => row.kind === 'forbidden' && row.source === 'handler' && row.step >= 4 && row.step <= 10 && row.expected.includes('저장소 변화 없음'));
  assert.ok(guarded.length >= 6);
  assert.ok(guarded.every((row) => row.actual.endsWith('저장소 변화 없음')));
});

test('실제로 실행한 판정·탐지·서버 함수의 값이 기대와 같다 (대표 행)', async () => {
  const { rows } = await local();
  const find = (step, kind, text) => rows.find((row) => row.step === step && row.kind === kind && row.title.includes(text));
  assert.equal(find(6, 'forbidden', '미등록').actual, 'deny · device_not_registered');
  assert.equal(find(7, 'forbidden', '복합 이상').actual, 'step_up · step_up_required');
  assert.equal(find(8, 'forbidden', '메모 전체 목록').actual, 'deny · route_not_allowed');
  assert.equal(find(8, 'forbidden', '반 공지 쓰기').actual, 'deny · zone_forbidden');
  assert.equal(find(9, 'forbidden', '121건').actual, 'propose_revocation · burst_read · 기기 1개');
  assert.equal(find(9, 'normal', '경계 120건').actual, 'observe');
  assert.equal(find(10, 'normal', '자기 메모를 사본으로 복원').actual, 'HTTP 200 · 내용 해시가 사본과 같음 · 다른 메모 그대로');
  assert.equal(find(11, 'forbidden', '쿠키 없이').actual, 'HTTP 403');
  assert.equal(find(11, 'forbidden', '자기 코드로 승인').actual, 'HTTP 403 · 상태 그대로 승인 대기');
  assert.equal(find(11, 'normal', '승인된 새 기기').actual, 'HTTP 200');
});

test('실행하지 않은 요청은 미실행으로 남고 실제 결과·요청 ID·확인 시각이 없으며 통과로 세지 않는다', async () => {
  const { rows, summary } = await local();
  const skipped = rows.filter((row) => row.result === 'not_run');
  assert.ok(skipped.length >= 20);
  for (const row of skipped) {
    assert.equal(row.actual, null, row.title);
    assert.equal(row.requestId, null, row.title);
    assert.equal(row.checkedAt, null, row.title);
    assert.equal(row.source, 'none', row.title);
    assert.ok(row.note.length > 0, `${row.title}: 미실행 이유`);
  }
  assert.equal(summary.notRun, skipped.length);
  assert.equal(summary.match + summary.mismatch + summary.notRun, summary.total);
  assert.equal(summary.measured, summary.match + summary.mismatch);
  // 실제 계정·환경변수·실제 DB·실제 회수가 필요한 요청이 미실행으로 들어 있다
  const text = skipped.map((row) => `${row.title} ${row.note}`).join('\n');
  for (const phrase of ['SUPABASE_PUBLISHABLE_KEY', '로그인 토큰', '실제 회수', '실제 DB', '실제 브라우저', '새 로그인 시각']) assert.ok(text.includes(phrase), phrase);
  // 배포 요청은 --deployed 없이는 모두 미실행이다
  const deployed = skipped.filter((row) => row.note.includes('--deployed'));
  assert.equal(deployed.length, 12);
});

test('41종 공격은 목록과 실측이 없어 모두 미실행이고 통과로 처리하지 않는다', async () => {
  const result = await local();
  assert.deepEqual(result.summary.attacks, { declared: 41, listed: 0, measured: 0, notRun: 41 });
  assert.equal(ATTACK_TOTAL, 41);
  const report = renderReport(result);
  assert.match(report, /41종 공격 방어: 선언 41종 · 목록 0건 · 실측 0건 · 미실행 41종 \(목록과 심판 판정이 없어 통과로 처리하지 않음\)/u);
  assert.ok(!result.rows.some((row) => /41종|공격 방어/u.test(row.title) && row.result === 'match'));
  assert.deepEqual(summarize([]).attacks, { declared: 41, listed: 0, measured: 0, notRun: 41 }, '행이 없어도 통과로 바뀌지 않는다');
});

test('표: 열과 줄 수가 맞고 머리말에 실측 대상의 차이를 밝힌다', async () => {
  const result = await local();
  const report = renderReport(result);
  const lines = report.split('\n');
  const header = lines.findIndex((line) => line.startsWith('| 단계 | 구분 |'));
  assert.equal(lines[header], '| 단계 | 구분 | 요청 | 기대 | 실제 | 결과 | 요청 ID | 확인 시각 | 출처 |');
  const body = lines.slice(header + 2).filter((line) => line.startsWith('| '));
  assert.equal(body.length, result.rows.length);
  for (const line of body) assert.equal(line.replaceAll('\\|', '').split('|').length, 11, line.slice(0, 60));
  assert.match(report, /배포된 시스템과 실제 Supabase를 실측한 것이 아닙니다/u);
  assert.match(report, /\*\*미실행\*\*은 실행하지 않은 요청이며 통과로 세지 않습니다/u);
  assert.match(report, /배포 주소 요청: 실행하지 않음\(--deployed 없음\)/u);
  assert.match(report, /요약: 전체 \d+건 · 실측 \d+건\(일치 \d+, 불일치 0\) · 미실행 \d+건/u);
});

test('불일치를 숨기지 않는다: 판정기가 잘못 허용하면 그 행이 불일치로 남고 종료 코드가 1이다', async () => {
  const broken = await runRecheck({ now: clock(), deps: { decide: async (request) => ({ schema: 'aleph.decision.v1', requestId: request.requestId, decision: 'allow', reasonCode: 'approved', ruleIds: ['x'] }) } });
  const bad = broken.rows.filter((row) => row.result === 'mismatch');
  assert.ok(bad.length >= 6, `불일치 ${bad.length}건`);
  assert.ok(bad.some((row) => row.step === 6 && row.kind === 'forbidden' && row.actual === 'allow · approved'));
  assert.equal(broken.summary.mismatch, bad.length);
  assert.equal(exitCodeFor(broken), 1);
  assert.equal(exitCodeFor(await local()), 0);
  // 요청 ID를 되돌려 주지 않는 판정기는 일치로 보지 않는다
  const noEcho = await runRecheck({ now: clock(), deps: { decide: async () => ({ decision: 'allow', reasonCode: 'approved' }) } });
  assert.ok(noEcho.rows.some((row) => row.step === 6 && row.kind === 'normal' && row.result === 'mismatch' && row.actual.includes('요청 ID 불일치')));
  // 탐지가 제안하지 않으면 9단계 금지 행이 불일치다
  const lax = await runRecheck({ now: clock(), deps: { detect: () => ({ action: 'observe' }) } });
  assert.ok(lax.rows.some((row) => row.step === 9 && row.kind === 'forbidden' && row.result === 'mismatch'));
  // 서버 함수가 금지 요청을 허용하면 금지 행이 불일치로 남는다
  const open = async (req, res) => { res.setHeader('Cache-Control', 'no-store'); res.status(200).json([]); };
  const laxApi = await runRecheck({ now: clock(), deps: { createNotesApi: () => ({ collection: open, item: open, restore: open }) } });
  assert.ok(laxApi.rows.some((row) => row.step === 3 && row.kind === 'forbidden' && row.result === 'mismatch' && row.actual === 'HTTP 200'));
  assert.ok(laxApi.summary.mismatch >= 8);
});

test('배포 요청: 주소를 주면 토큰 없는 요청만 실제로 보내고 응답 코드를 그대로 기록한다', async () => {
  const sent = [];
  const fetchImpl = async (url, init) => {
    sent.push({ path: url.pathname, method: init.method, headers: init.headers });
    const headers = new Headers({ 'x-vercel-id': 'icn1::abc12-1700000000000-0123456789ab' });
    const json = (status, body) => new Response(body, { status, headers });
    if (url.pathname === '/') return json(200, '<title>BYTE BACK 내 자료실</title>');
    if (url.pathname === '/data.json') return json(200, '{"notes":[]}');
    if (init.method === 'PATCH') return json(405, '{}');
    return json(401, '{}');
  };
  const result = await runRecheck({ now: clock(), baseUrl: 'https://example-app.vercel.app', fetchImpl });
  const deployed = result.rows.filter((row) => row.source === 'deployed');
  assert.equal(deployed.length, 12);
  for (const row of deployed) {
    assert.equal(row.result, 'match', `${row.title}: ${row.actual}`);
    assert.match(row.requestId, /^[0-9a-f-]{36} \(vercel: icn1::abc12-/u);
    assert.match(row.checkedAt, /^2026-/u);
  }
  assert.equal(sent.length, 12);
  for (const call of sent) {
    assert.match(call.headers['x-request-id'], UUID);
    assert.ok(!('cookie' in call.headers) && !('Cookie' in call.headers));
    assert.ok(call.headers.Authorization === undefined || call.headers.Authorization === 'Bearer aaa.bbb.ccc', '가짜 토큰 외의 로그인 정보를 보내지 않음');
  }
  assert.deepEqual([...new Set(sent.map((call) => call.method))].sort(), ['DELETE', 'GET', 'PATCH', 'POST']);
  assert.equal(result.rows.filter((row) => row.note.includes('--deployed')).length, 0);
  assert.match(renderReport(result), /배포 주소 요청: 실행/u);
});

test('배포 요청이 틀린 응답을 받거나 실패하면 불일치로 남는다', async () => {
  const wrong = await runRecheck({ now: clock(), baseUrl: 'https://example-app.vercel.app', fetchImpl: async () => new Response('{"notes":[1]}', { status: 200 }) });
  const wrongRows = wrong.rows.filter((row) => row.source === 'deployed');
  const pageKey = '배포된 첫 화면에 접속값 형태가 없음';
  const wrongOnes = wrongRows.filter((row) => row.title !== pageKey);
  assert.equal(wrongOnes.length, 11);
  assert.ok(wrongOnes.every((row) => row.result === 'mismatch'), '모두 200이면 401·405·메모 0건 기대는 모두 불일치');
  assert.equal(wrongRows.find((row) => row.title === pageKey).result, 'match', '접속값이 없는 응답은 그대로 일치로 기록');
  assert.ok(wrongRows.some((row) => row.actual === 'HTTP 200'));
  const down = await runRecheck({ now: clock(), baseUrl: 'https://example-app.vercel.app', fetchImpl: async () => { throw new Error('network'); } });
  const downRows = down.rows.filter((row) => row.source === 'deployed');
  assert.ok(downRows.length === 12 && downRows.every((row) => row.result === 'mismatch' && row.actual === '요청 실패 · 응답 없음'));
  assert.equal(exitCodeFor(down), 1);
});

test('표와 저장 결과에는 토큰, 쿠키 값, 해시 원문, 저장소 키, 메모 본문이 없다', async () => {
  const result = await local();
  const text = `${renderReport(result)}\n${JSON.stringify(result)}`;
  for (const secret of ['tokenA', 'tokenB', 'recheck-local-only', 'recheck.invalid', 'B가 침해 전에 쓴 가상 내용', '침해된 내용', 'A의 내용', '재확인 내용', 'Bearer']) {
    assert.ok(!text.includes(secret), secret);
  }
  assert.doesNotMatch(text, /[0-9a-f]{13,}/iu, '12자를 넘는 16진수 문자열 없음');
  assert.doesNotMatch(readFileSync(`${root}src/recheck.mjs`, 'utf8'), /\b(writeFile|appendFile|mkdir|unlink|rename)\w*\(/u, '표 만들기 모듈은 파일을 쓰지 않는다');
});

test('명령: 인자 검사, 파일 저장, 종료 코드', () => {
  assert.deepEqual(parseArgs([]).baseUrl, null);
  assert.equal(parseArgs(['--deployed', 'https://example-app.vercel.app']).baseUrl, 'https://example-app.vercel.app');
  assert.match(parseArgs(['--out', 'some/dir']).out, /some[\\/]dir$/u);
  for (const argv of [['--deployed'], ['--deployed', 'http://example.com'], ['--deployed', 'https://u:p@example.com'], ['--deployed', 'https://example.com/path'],
    ['--deployed', 'https://example.com/?q=1'], ['--deployed', 'not a url'], ['--token', 'x'], ['--out'], ['--deployed', '--out']]) {
    assert.throws(() => parseArgs(argv), UsageError, argv.join(' '));
  }
  const out = mkdtempSync(join(tmpdir(), 'recheck-'));
  const run = spawnSync(process.execPath, [join(root, 'scripts/recheck.mjs'), '--out', out], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /\| 단계 \| 구분 \| 요청 \| 기대 \| 실제 \| 결과 \| 요청 ID \| 확인 시각 \| 출처 \|/u);
  assert.match(run.stdout, /저장: .*recheck-\d{8}T\d{6}Z\.md \/ \.json/u);
  const files = readdirSync(out).sort();
  assert.equal(files.length, 2);
  assert.ok(files[0].endsWith('.json') && files[1].endsWith('.md'));
  const saved = JSON.parse(readFileSync(join(out, files[0]), 'utf8'));
  assert.equal(saved.summary.mismatch, 0);
  assert.equal(saved.summary.attacks.notRun, 41);
  const bad = spawnSync(process.execPath, [join(root, 'scripts/recheck.mjs'), '--deployed', 'http://insecure.example'], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /https 주소/u);
  assert.ok(existsSync(join(root, 'scripts/recheck.mjs')));
});
