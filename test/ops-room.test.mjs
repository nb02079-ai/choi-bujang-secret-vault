import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { setDeviceStatus, viewState } from '../public/app-shell.js';
import { OPS_NOTE, OPS_SCHEMA, buildOpsView } from '../public/ops-room.js';
import { DEVICE_COOKIE, createDeviceCheck } from '../src/device-api.mjs';
import { createOpsApi } from '../src/ops-api.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const html = readFileSync(`${root}public/index.html`, 'utf8');
const USER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
// 키 모양 가짜 값은 실행할 때 조립해 저장소 파일에 키 형태 문자열이 남지 않게 합니다.
const STORE_VALUE = [['sb', ['sec', 'ret'].join(''), ''].join('_'), 'room_value'].join('');
const sha = (value) => createHash('sha256').update(value).digest('hex');
const NOW = Date.parse('2026-10-14T00:00:00Z');
const COOKIE = 'a'.repeat(43);
const stamp = (minutes) => new Date(NOW + minutes * 60000).toISOString();
const hex = (char) => char.repeat(64);

// ---- 표시 규칙(buildOpsView) 단위 시험 ----
const goodSummary = () => ({
  schema: OPS_SCHEMA, readAt: stamp(0),
  decider: { kind: 'definition', source: 'code', ruleIds: ['device_registered', 'step_up_required'],
    results: { recorded: false, reason: '판정기는 판정 결과를 저장하지 않아 집계할 수 없습니다.' } },
  detection: { kind: 'definition', source: 'code', rule: { windowSeconds: 600, threshold: 120, reasonCode: 'burst_read' }, events: { recorded: false, reason: '탐지 사건을 남기는 저장소가 없어 사건 수를 알 수 없습니다.' } },
  revocation: { confirmed: true, source: 'vault_devices', total: 3, truncated: false, counts: { pending: 1, approved: 1, denied: 0, revoked: 1, other: 0 },
    records: [
      { ref: 'a1a1a1a1', status: 'approved', createdAt: stamp(-5), decidedAt: stamp(-4), expiresAt: stamp(5) },
      { ref: 'a2a2a2a2', status: 'pending', createdAt: stamp(-3), decidedAt: null, expiresAt: stamp(7) },
      { ref: 'a3a3a3a3', status: 'revoked', createdAt: stamp(-2), decidedAt: stamp(-1), expiresAt: stamp(9) },
    ], enforcement: { run: false, reason: '실제 집행은 심판이 확인합니다.' } },
  recovery: { confirmed: true, source: 'x', backups: { confirmed: true, total: 1, truncated: false, records: [{ ref: 'c1c1c1c1', hash12: '111111111111', at: stamp(-9) }] },
    restores: { confirmed: true, total: 1, truncated: false, records: [{ ref: 'c1c1c1c1', hash12: '222222222222', outcome: 'restored', at: stamp(-3) }] },
    policySnapshot: { confirmed: false, reason: '정책 사본은 로컬 파일이라 서버가 버전을 읽을 수 없습니다.' } },
  notRun: [{ id: 'attack_verdict', text: '41종 공격 방어 여부는 심판이 판정하며 이 화면은 통과 근거가 아닙니다.' }],
});
const flat = (view) => [...view.cards.flatMap((card) => [card.title, card.tag, ...card.lines, ...card.records]), ...view.notRun].join('\n');

test('표시 규칙: 정의, 확인됨, 미확인을 구분하고 기록이 없는 항목은 미기록·미실행으로 적는다', () => {
  const view = buildOpsView(goodSummary());
  assert.equal(view.note, OPS_NOTE);
  assert.match(view.note, /통과 근거가 아니며 판정은 심판이 합니다/u);
  assert.deepEqual(view.cards.map((card) => [card.id, card.tag]), [['decider', '정의'], ['detection', '정의'], ['revocation', '확인됨'], ['recovery', '확인됨']]);
  const text = flat(view);
  assert.match(text, /규칙 이름\(코드의 정의, 판정 결과가 아님\): device_registered, step_up_required/u);
  assert.doesNotMatch(text, /규칙 [0-9]+개|구역 경로|정책 지문/u, '화면이 개수나 지문을 만들어 보이지 않는다');
  assert.match(text, /판정 결과 집계: 미기록/u);
  assert.match(text, /탐지 사건: 미기록/u);
  assert.match(text, /600초 안에 GET 120건 초과, 이유 코드 burst_read/u);
  assert.match(text, /내 기기 3개/u);
  assert.match(text, /승인 대기 1, 승인됨 1, 거부됨 0, 폐기됨 1, 기타 0/u);
  assert.doesNotMatch(text, /대기 만료/u);
  assert.match(text, /실제 회수 집행: 미실행/u);
  assert.match(text, /정책 사본 버전: 미확인/u);
  assert.match(text, /기기 a1a1a1a1 · 승인됨/u);
  assert.match(text, /복원 메모 c1c1c1c1 · 해시 222222222222 · restored/u);
  assert.equal(view.notRun.length, 1);
  assert.match(view.readAt, /^2026-10-14 00:00:00 UTC$/u);
  // 화면 수치와 가린 기록 줄 수가 같다
  const revocation = view.cards.find((card) => card.id === 'revocation');
  assert.equal(revocation.records.length, 3);
  assert.ok(revocation.lines[0].includes('내 기기 3개'));
});

test('표시 규칙: 서버가 읽지 못한 구역과 잘못된 응답은 미확인이고 성공 문구를 만들지 않는다', () => {
  const partial = goodSummary();
  partial.revocation = { confirmed: false, source: 'vault_devices', reason: '이번 요청에서 읽지 못했습니다.', enforcement: { run: false, reason: '심판이 확인합니다.' } };
  partial.recovery.restores = { confirmed: false, source: 'vault_restore_audit', reason: '이번 요청에서 읽지 못했습니다.' };
  const view = buildOpsView(partial);
  assert.equal(view.cards.find((card) => card.id === 'revocation').tag, '미확인');
  assert.equal(view.cards.find((card) => card.id === 'decider').tag, '정의');
  const text = flat(view);
  assert.match(text, /기기 승인 기록을 읽지 못했습니다/u);
  assert.match(text, /복원 기록을 읽지 못했습니다/u);
  assert.doesNotMatch(text, /내 기기 [0-9]/u);
  for (const bad of [undefined, null, 7, 'x', [], {}, { schema: 'other' }, { ...goodSummary(), schema: 'vault.ops.summary.v0' }]) {
    const view2 = buildOpsView(bad);
    assert.equal(view2.cards.length, 4);
    assert.ok(view2.cards.every((card) => card.tag === '미확인'), JSON.stringify(bad));
    assert.deepEqual(view2.notRun, []);
    assert.equal(view2.readAt, null);
  }
  assert.doesNotMatch(flat(buildOpsView(null)), /성공|통과했|방어 완료|클리어|정상 작동/u);
});

test('표시 규칙: 서버 수치와 가린 기록이 맞지 않으면 숫자를 보이지 않고 미확인으로 둔다', () => {
  const cases = {
    '총수가 목록보다 큼': (s) => { s.revocation.total = 14; },
    '총수가 목록보다 작음': (s) => { s.revocation.total = 2; },
    '상태별 수가 목록과 다름': (s) => { s.revocation.counts.approved = 2; },
    '모르는 상태 값': (s) => { s.revocation.records[0].status = 'expired'; },
    'truncated 값이 없음': (s) => { delete s.revocation.truncated; },
    '상태별 수가 없음': (s) => { delete s.revocation.counts; },
  };
  for (const [label, mutate] of Object.entries(cases)) {
    const summary = goodSummary();
    mutate(summary);
    const card = buildOpsView(summary).cards.find((item) => item.id === 'revocation');
    assert.equal(card.tag, '미확인', label);
    assert.doesNotMatch([...card.lines, ...card.records].join('\n'), /내 기기 [0-9]|승인 대기 [0-9]/u, label);
    assert.deepEqual(card.records, [], label);
  }
  const summary = goodSummary();
  summary.recovery.backups.total = 9;
  const card = buildOpsView(summary).cards.find((item) => item.id === 'recovery');
  assert.doesNotMatch(card.lines.join('\n'), /사본 [0-9]+건/u);
  assert.match(card.lines.join('\n'), /사본: 서버 응답의 수치와 가린 기록이 맞지 않아/u);
  assert.match(card.lines.join('\n'), /복원 기록 1건/u);
  assert.equal(card.tag, '미확인', '맞지 않는 구역이 하나라도 있으면 확인됨으로 표시하지 않는다');
});

test('표시 규칙: 읽기 한도에서 잘린 기록은 이상(한도까지만 표시)으로 알린다', () => {
  const summary = goodSummary();
  summary.revocation.records = Array.from({ length: 100 }, (_, index) => ({ ref: index.toString(16).padStart(8, '0'), status: 'pending', createdAt: stamp(-index), decidedAt: null, expiresAt: null }));
  summary.revocation.total = 100;
  summary.revocation.truncated = true;
  summary.revocation.counts = { pending: 100, approved: 0, denied: 0, revoked: 0, other: 0 };
  const card = buildOpsView(summary).cards.find((item) => item.id === 'revocation');
  assert.equal(card.tag, '확인됨');
  assert.equal(card.records.length, 100);
  assert.match(card.lines[0], /내 기기 100개 이상\(읽기 한도 100건까지만 표시\)/u);
});

test('표시 규칙: 모든 값은 형식을 검사한 글자로만 쓰고 이상한 값은 -로 바꾼다', () => {
  const odd = goodSummary();
  odd.decider.ruleIds = ['<img src=x>', 'device_registered', 7];
  odd.detection.rule = { windowSeconds: -1, threshold: 1.5, reasonCode: '<b>' };
  odd.revocation.records = [{ ref: '<b>', status: 'pending', createdAt: 'x', decidedAt: null }, { ref: 'zz', status: 'approved', createdAt: stamp(0), decidedAt: stamp(1) }, { status: 'revoked' }];
  odd.revocation.total = 3;
  odd.revocation.counts = { pending: 1, approved: 1, denied: 0, revoked: 1, other: 0 };
  odd.recovery.restores.records = [{ ref: 'ZZZZZZZZ', hash12: 'full'.repeat(20), outcome: '<x>', at: 'not-a-date' }];
  odd.notRun = [null, 'x', { text: 7 }, { text: '가'.repeat(500) }];
  const view = buildOpsView(odd);
  const text = flat(view);
  assert.doesNotMatch(text, /<script>|<img|<b>|<i>|<x>/u);
  assert.match(text, /규칙 이름\(코드의 정의, 판정 결과가 아님\): device_registered/u);
  assert.match(text, /- 초 안에 GET -건 초과|-초 안에 GET -건 초과/u);
  assert.match(text, /기기 - · 승인 대기 · 요청 시각 미상/u);
  assert.match(text, /복원 메모 - · 해시 - · - · 시각 미상/u);
  assert.equal(view.notRun.length, 1);
  assert.ok(view.notRun[0].length <= 200);
});

// ---- 화면 실행: 실제 서버 코드가 만든 응답을 화면 스크립트에 넣어 수치를 대조 ----
const AsyncFunction = Object.getPrototypeOf(async function noop() {}).constructor;
function pageScript() {
  const text = html.replaceAll('\r\n', '\n');
  const start = text.indexOf('<script type="module">\n') + '<script type="module">\n'.length;
  const code = text.slice(start, text.indexOf('</script>', start));
  return code
    .replace(/^\s*import \{ setDeviceStatus, viewState \} from '\/app-shell\.js';\s*$/mu, 'const { setDeviceStatus, viewState } = shell;')
    .replace(/^\s*import \{ buildOpsView \} from '\/ops-room\.js';\s*$/mu, 'const { buildOpsView } = opsRoom;');
}
function openPage(serve) {
  const nodes = new Map();
  const make = () => ({
    hidden: false, textContent: '', value: '', disabled: false, dataset: {}, children: [], className: '', listeners: {},
    classList: { toggle() {}, add() {}, remove() {} }, maxLength: 0, required: false, type: '', rows: 0,
    addEventListener(type, handler) { this.listeners[type] = handler; },
    append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; },
    setAttribute() {}, focus() {}, reset() {},
  });
  const document = {
    querySelector(selector) { if (!nodes.has(selector)) nodes.set(selector, make()); return nodes.get(selector); },
    createElement() { return make(); },
  };
  const calls = [];
  const fetch = async (path, init = {}) => {
    calls.push({ path, method: init.method ?? 'GET' });
    const reply = await serve(path, init);
    return { ok: reply.status >= 200 && reply.status < 300, status: reply.status, json: async () => reply.body };
  };
  const form = document.querySelector('#login-form');
  form.email = { value: 'a@example.test' };
  form.password = { value: 'not-a-real-password' };
  const ready = new AsyncFunction('document', 'window', 'fetch', 'shell', 'opsRoom', pageScript())(
    document, { confirm: () => true }, fetch, { setDeviceStatus, viewState }, { buildOpsView });
  const settle = async () => { for (let index = 0; index < 14; index += 1) await new Promise((resolve) => setImmediate(resolve)); };
  const q = (selector) => document.querySelector(selector);
  const text = (node) => [node.textContent, ...node.children.map(text)].join('\n');
  return { ready, calls, q, settle, text, login: async () => { await q('#login-form').listeners.submit({ preventDefault() {} }); await settle(); } };
}
const session = () => ({ status: 200, body: { access_token: 'access.test.value', refresh_token: 'refresh_test_value', expires_at: Math.floor(Date.now() / 1000) + 3600, email: 'a@example.test' } });

function serverWorld(failTables = []) {
  const tables = {
    vault_devices: [
      { id: 'a1a1a1a1-0000-4000-8000-000000000001', owner_id: USER_A, secret_sha256: sha(COOKIE), status: 'approved', request_code: 'ABCD2345', created_at: stamp(-600), decided_at: stamp(-590), expires_at: stamp(-500) },
      { id: 'a2a2a2a2-0000-4000-8000-000000000002', owner_id: USER_A, secret_sha256: sha('x'), status: 'pending', request_code: 'WXYZ6789', created_at: stamp(-5), decided_at: null, expires_at: stamp(10) },
      { id: 'a3a3a3a3-0000-4000-8000-000000000003', owner_id: USER_A, secret_sha256: sha('y'), status: 'revoked', request_code: 'QRST2345', created_at: stamp(-300), decided_at: stamp(-100), expires_at: stamp(-200) },
    ],
    vault_notes_backup: [
      { id: 'c1c1c1c1-0000-4000-8000-000000000011', owner_id: USER_A, title: 'SECRET-TITLE', content: 'SECRET-BODY', content_sha256: hex('1'), backed_up_at: stamp(-500) },
    ],
    vault_restore_audit: [
      { id: 1, note_id: 'c1c1c1c1-0000-4000-8000-000000000011', owner_id: USER_A, content_sha256: hex('2'), outcome: 'restored', restored_at: stamp(-50) },
      { id: 2, note_id: 'c1c1c1c1-0000-4000-8000-000000000011', owner_id: USER_A, content_sha256: hex('3'), outcome: 'restored', restored_at: stamp(-10) },
    ],
  };
  const fetchImpl = async (url, init) => {
    const name = url.pathname.split('/').pop();
    if (failTables.includes(name)) return new Response('{}', { status: 500 });
    const rows = tables[name] ?? [];
    const query = Object.fromEntries(url.searchParams);
    const filters = Object.entries(query).filter(([key, value]) => !['select', 'limit', 'order'].includes(key) && value.startsWith('eq.'));
    const hit = rows.filter((row) => filters.every(([key, value]) => String(row[key]) === value.slice(3)));
    const columns = query.select?.split(',');
    return Response.json(hit.map((row) => (columns ? Object.fromEntries(columns.map((key) => [key, row[key]])) : row)));
  };
  const env = { SUPABASE_URL: 'https://example-project.supabase.co', SUPABASE_SECRET_KEY: STORE_VALUE };
  const now = () => NOW;
  const verify = async (authorization) => (authorization === 'Bearer access.test.value' ? { kind: 'student', userId: USER_A } : null);
  const api = createOpsApi({ verify, env, fetchImpl, now, deviceCheck: createDeviceCheck({ env, fetchImpl, now }) });
  // 브라우저처럼 same-origin 요청에는 기기 쿠키를 붙입니다. 화면 스크립트는 쿠키 값을 모릅니다.
  const serveOps = async (init) => {
    const res = { headers: {}, statusCode: 0, body: undefined, setHeader() {}, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
    const headers = Object.fromEntries(Object.entries(init.headers ?? {}).map(([key, value]) => [key.toLowerCase(), value]));
    if (init.credentials === 'same-origin') headers.cookie = `${DEVICE_COOKIE}=${COOKIE}`;
    await api.summary({ method: init.method ?? 'GET', url: '/api/ops/summary', headers }, res);
    return { status: res.statusCode, body: res.body };
  };
  return { tables, serveOps };
}

test('화면 실행: 화면의 수치와 가린 서버 기록이 서로 맞고 가상 메모 본문은 어디에도 없다', async () => {
  const w = serverWorld();
  const warn = mock.method(console, 'warn', () => {});
  try {
    let deviceStatus = 'unverified';
    const page = openPage(async (path, init) => {
      if (path === '/api/auth/login') return session();
      if (path === '/api/device/status') return { status: 200, body: { status: deviceStatus } };
      if (path === '/api/ops/summary') return w.serveOps(init);
      if (path === '/api/notes') return { status: 200, body: [{ id: 'e1e1e1e1-0000-4000-8000-000000000021', title: 'SECRET-NOTE', body: 'SECRET-NOTE-BODY' }] };
      return { status: 404, body: {} };
    });
    await page.ready;
    await page.settle();
    assert.equal(page.q('#ops-room').hidden, true, '로그인 전에는 작전실이 없다');
    await page.login();
    assert.equal(page.q('#ops-room').hidden, true, '승인 전에는 작전실이 없다');
    assert.equal(page.calls.some((call) => call.path === '/api/ops/summary'), false, '승인 전에는 작전실 요청도 보내지 않는다');
    assert.equal(page.text(page.q('#ops-cards')).trim(), '');

    deviceStatus = 'approved';
    await page.q('#device-refresh').listeners.click();
    await page.settle();
    assert.equal(page.q('#ops-room').hidden, false);
    assert.equal(page.calls.filter((call) => call.path === '/api/ops/summary').length, 1);
    const shown = page.text(page.q('#ops-cards'));

    // 원본 기록의 집계를 시험이 직접 계산해 화면 숫자와 대조한다
    const devices = w.tables.vault_devices.filter((row) => row.owner_id === USER_A);
    const count = (state) => devices.filter((row) => row.status === state).length;
    assert.ok(shown.includes(`내 기기 ${devices.length}개`));
    assert.ok(shown.includes(`승인 대기 ${count('pending')}, 승인됨 ${count('approved')}, 거부됨 ${count('denied')}, 폐기됨 ${count('revoked')}, 기타 0`));
    assert.ok(!shown.includes('대기 만료'), '현재 시각으로 계산한 상태는 화면에 없다');
    assert.ok(shown.includes(`사본 ${w.tables.vault_notes_backup.length}건`));
    assert.ok(shown.includes(`복원 기록 ${w.tables.vault_restore_audit.length}건`));
    // 가린 기록: 번호 앞 8자와 해시 앞 12자가 서버 기록과 같다
    for (const row of devices) assert.ok(shown.includes(`기기 ${row.id.slice(0, 8)} ·`), row.id.slice(0, 8));
    for (const row of w.tables.vault_restore_audit) assert.ok(shown.includes(`복원 메모 ${row.note_id.slice(0, 8)} · 해시 ${row.content_sha256.slice(0, 12)} · restored`));
    assert.ok(shown.includes(`사본 메모 c1c1c1c1 · 해시 ${hex('1').slice(0, 12)}`));
    // 줄 수도 기록 수와 맞는다
    const recordLines = (prefix) => shown.split('\n').filter((line) => line.startsWith(prefix)).length;
    assert.equal(recordLines('기기 '), devices.length);
    assert.equal(recordLines('복원 메모 '), w.tables.vault_restore_audit.length);
    assert.equal(recordLines('사본 메모 '), w.tables.vault_notes_backup.length);

    // 미실행·미기록은 따로 보인다
    assert.ok(!/규칙 [0-9]+개|구역 경로|정책 지문/u.test(shown), '화면에 계산한 규칙 수나 지문이 없다');
    for (const phrase of ['판정 결과 집계: 미기록', '탐지 사건: 미기록', '실제 회수 집행: 미실행', '정책 사본 버전: 미확인', '미실행·미기록 안내']) {
      assert.ok(shown.includes(phrase), phrase);
    }
    assert.match(shown, /41종 공격 방어 여부는 심판이 판정하며 이 화면은 통과 근거가 아닙니다/u);
    // 가상 메모 본문과 비밀 값은 화면 어디에도 없다
    // 작전실 영역 전체(제목, 안내, 카드, 메시지)에서 확인한다. 메모 목록 화면은 기존 자료 화면이라 따로 둔다.
    const room = page.text(page.q('#ops-room'));
    for (const secret of ['SECRET-', COOKIE, sha(COOKIE), 'ABCD2345', 'WXYZ6789', 'QRST2345', USER_A, 'access.test.value', STORE_VALUE, hex('1'), hex('2'), hex('3')]) {
      assert.ok(!room.includes(secret), secret.slice(0, 12));
      assert.ok(!shown.includes(secret), secret.slice(0, 12));
    }
    assert.doesNotMatch(shown, /성공|통과했|방어 완료|클리어|정상 작동/u, '화면이 스스로 만든 성공 문구가 없다');
  } finally { warn.mock.restore(); }
});

test('화면 실행: 서버가 한 표를 읽지 못했다고 알리면 그 구역은 미확인으로 보이고 숫자를 지어내지 않는다', async () => {
  const w = serverWorld(['vault_restore_audit']);
  const page = openPage(async (path, init) => {
    if (path === '/api/auth/login') return session();
    if (path === '/api/device/status') return { status: 200, body: { status: 'approved' } };
    if (path === '/api/ops/summary') return w.serveOps(init);
    return { status: 200, body: [] };
  });
  await page.ready;
  await page.login();
  const shown = page.text(page.q('#ops-cards'));
  assert.ok(shown.includes('내 기기 3개'));
  assert.ok(shown.includes('복원 기록을 읽지 못했습니다.'));
  assert.ok(!/복원 기록 [0-9]+건/u.test(shown));
  assert.ok(!shown.includes('복원 메모'));
  assert.ok(shown.includes('사본 1건'));
});

test('화면 실행: 작전실 요청이 실패하거나 서버가 기기 승인을 요구하면 숫자를 보이지 않는다', async () => {
  const failing = openPage(async (path) => {
    if (path === '/api/auth/login') return session();
    if (path === '/api/device/status') return { status: 200, body: { status: 'approved' } };
    if (path === '/api/ops/summary') return { status: 500, body: { error: '서버 설정이 아직 끝나지 않았습니다.' } };
    return { status: 200, body: [] };
  });
  await failing.ready;
  await failing.login();
  assert.equal(failing.text(failing.q('#ops-cards')).trim(), '');
  assert.match(failing.q('#ops-message').textContent, /서버 설정이 아직 끝나지 않았습니다/u);

  const blocked = openPage(async (path) => {
    if (path === '/api/auth/login') return session();
    if (path === '/api/device/status') return { status: 200, body: { status: 'approved' } };
    if (path === '/api/ops/summary') return { status: 403, body: { error: '기기 승인이 필요합니다.', code: 'device_not_approved' } };
    return { status: 200, body: [] };
  });
  await blocked.ready;
  await blocked.login();
  assert.equal(blocked.q('#ops-room').hidden, true);
  assert.equal(blocked.q('#editor').hidden, true);
  assert.equal(blocked.q('#device-status').textContent, '확인 전');
  assert.equal(blocked.text(blocked.q('#ops-cards')).trim(), '');
});

test('화면 실행: 로그아웃하면 작전실이 닫히고 내용이 사라진다. 새로고침 단추는 서버를 다시 부른다', async () => {
  const w = serverWorld();
  const page = openPage(async (path, init) => {
    if (path === '/api/auth/login') return session();
    if (path === '/api/auth/logout') return { status: 200, body: {} };
    if (path === '/api/device/status') return { status: 200, body: { status: 'approved' } };
    if (path === '/api/ops/summary') return w.serveOps(init);
    return { status: 200, body: [] };
  });
  await page.ready;
  await page.login();
  assert.ok(page.text(page.q('#ops-cards')).includes('내 기기 3개'));
  w.tables.vault_devices.push({ id: 'a9a9a9a9-0000-4000-8000-000000000009', owner_id: USER_A, secret_sha256: sha('z'), status: 'denied', request_code: 'AAAA2222', created_at: stamp(-1), decided_at: stamp(0), expires_at: stamp(5) });
  await page.q('#ops-refresh').listeners.click();
  await page.settle();
  assert.equal(page.calls.filter((call) => call.path === '/api/ops/summary').length, 2);
  assert.ok(page.text(page.q('#ops-cards')).includes('내 기기 4개'), '새로고침하면 새 기록이 수치에 반영된다');
  assert.ok(page.text(page.q('#ops-cards')).includes('기기 a9a9a9a9 ·'));
  await page.q('#logout').listeners.click();
  await page.settle();
  assert.equal(page.q('#ops-room').hidden, true);
  assert.equal(page.text(page.q('#ops-cards')).trim(), '');
});

test('화면 소스: 작전실 패널은 처음에 숨겨져 있고 값은 글자로만 쓰며 새 브라우저 저장소를 쓰지 않는다', () => {
  assert.match(html, /<section class="ops" id="ops-room"[^>]*hidden>/u);
  assert.match(html, /통과 근거가 아니며 판정은 심판이 합니다/u);
  const script = pageScript();
  assert.doesNotMatch(script, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(/u);
  assert.doesNotMatch(html, /sessionStorage|localStorage|indexedDB|document\.cookie/u);
  assert.equal((script.match(/'\/api\/ops\/summary'/gu) ?? []).length, 1);
  assert.match(script, /if \(deviceState\.status !== 'approved'\) return;/u);
});
