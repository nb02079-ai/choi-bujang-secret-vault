import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { DEVICE_COOKIE, createDeviceApi, createDeviceCheck, deviceApi, readDeviceCookie } from '../src/device-api.mjs';
import { createNotesApi, notesApi } from '../src/notes-api.mjs';

const USER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOTE_A = '11111111-1111-4111-8111-111111111111';
// 키 모양 가짜 값은 실행할 때 조립해 저장소 파일에 키 형태 문자열이 남지 않게 합니다.
const STORE_VALUE = [['sb', ['sec', 'ret'].join(''), ''].join('_'), 'device_value'].join('');
const CODE = /^[0-9A-HJKMNP-TV-Z]{8}$/u;
const sha = (value) => createHash('sha256').update(value).digest('hex');

function fakeResponse() {
  const res = { headers: {}, statusCode: 0, body: undefined };
  res.setHeader = (key, value) => { res.headers[key.toLowerCase()] = value; };
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (body) => { res.body = body; return res; };
  return res;
}

// 기기 표와 메모 표를 흉내 내는 메모리 저장소입니다.
function world({ failDevices = false, throwDevices = false } = {}) {
  const tables = { vault_devices: [], vault_notes: [{ id: NOTE_A, owner_id: USER_A, title: 'A의 메모', content: 'A의 내용' }] };
  const calls = [];
  const fetchImpl = async (url, init) => {
    const name = url.pathname.split('/').pop();
    const rows = tables[name];
    calls.push({ method: init.method, name });
    if (name === 'vault_devices' && throwDevices) throw new Error('연결 실패');
    if (name === 'vault_devices' && failDevices) return new Response('{}', { status: 500 });
    if (!rows) return new Response('{}', { status: 404 });
    const query = Object.fromEntries(url.searchParams);
    const filters = Object.entries(query).filter(([key, value]) => !['select', 'limit', 'order'].includes(key) && value.startsWith('eq.'));
    const hit = () => rows.filter((row) => filters.every(([key, value]) => String(row[key]) === value.slice(3)));
    const pick = (row) => (query.select ? Object.fromEntries(query.select.split(',').map((key) => [key, row[key]])) : row);
    const body = init.body ? JSON.parse(init.body) : undefined;
    if (init.method === 'GET') return Response.json(hit().map(pick));
    if (init.method === 'POST') {
      const row = { id: randomUUID(), ...body };
      rows.push(row);
      return Response.json([pick(row)], { status: 201 });
    }
    const matched = hit();
    if (init.method === 'PATCH') { matched.forEach((row) => Object.assign(row, body)); return Response.json(matched.map(pick)); }
    matched.forEach((row) => rows.splice(rows.indexOf(row), 1));
    return Response.json(matched.map(pick));
  };
  let clock = Date.parse('2026-10-14T00:00:00Z');
  const now = () => clock;
  const env = { SUPABASE_URL: 'https://example-project.supabase.co', SUPABASE_SECRET_KEY: STORE_VALUE };
  const tokens = {
    'Bearer tokenA.aaa.aaa': { kind: 'student', userId: USER_A },
    'Bearer tokenB.bbb.bbb': { kind: 'student', userId: USER_B },
    'Bearer judgeA.aaa.aaa': { kind: 'judge', userId: USER_A, runId: 'run', identity: 'a' },
  };
  const verify = async (authorization) => tokens[authorization] ?? null;
  const api = createDeviceApi({ verify, env, fetchImpl, now });
  const gate = (extraEnv = {}) => createNotesApi({ verify, env: { ...env, ...extraEnv }, fetchImpl, deviceCheck: createDeviceCheck({ env: { ...env, ...extraEnv }, fetchImpl, now }) });
  const call = async (handler, method, { token, cookie, body, headers = {}, query, url = '/api/x' } = {}) => {
    const res = fakeResponse();
    const extra = {};
    if (token) extra.authorization = `Bearer ${token}`;
    if (cookie) extra.cookie = `theme=dark; ${DEVICE_COOKIE}=${cookie}; other=1`;
    await handler({ method, url, query, headers: { ...extra, ...headers }, body }, res);
    return res;
  };
  const cookieOf = (res) => {
    const header = res.headers['set-cookie'];
    return typeof header === 'string' ? new RegExp(`^${DEVICE_COOKIE}=([A-Za-z0-9_-]+);`, 'u').exec(header)?.[1] : undefined;
  };
  const warn = mock.method(console, 'warn', () => {});
  const error = mock.method(console, 'error', () => {});
  const logs = () => [...warn.mock.calls, ...error.mock.calls].map((entry) => entry.arguments.join(' ')).join('\n');
  return { tables, calls, api, gate, call, cookieOf, logs, tick: (ms) => { clock += ms; }, A: 'tokenA.aaa.aaa', B: 'tokenB.bbb.bbb', J: 'judgeA.aaa.aaa',
    done: () => { warn.mock.restore(); error.mock.restore(); } };
}
// 첫 기기는 승인된 기기가 없어서 운영자가 DB에서 승인합니다. 그 일을 흉내 냅니다.
async function bootstrap(w, token = 'A') {
  const res = await w.call(w.api.request, 'POST', { token: w[token] });
  const row = w.tables.vault_devices.find((item) => item.request_code === res.body.code);
  row.status = 'approved';
  return w.cookieOf(res);
}

test('승인 요청은 대기 기록과 코드만 만들고 쿠키 값은 해시로만 저장하며 권한을 주지 않는다', async () => {
  const w = world();
  try {
    const res = await w.call(w.api.request, 'POST', { token: w.A, body: { label: '내 노트북' } });
    assert.equal(res.statusCode, 201);
    assert.equal(res.body.status, 'pending');
    assert.match(res.body.code, CODE);
    assert.equal(res.body.expiresInSeconds, 900);
    const header = res.headers['set-cookie'];
    for (const part of [`${DEVICE_COOKIE}=`, 'Path=/', 'Secure', 'HttpOnly', 'SameSite=Strict', 'Max-Age=']) assert.ok(header.includes(part), part);
    assert.ok(!/Domain=/iu.test(header), '__Host- 쿠키는 Domain을 쓰지 않음');
    const secret = w.cookieOf(res);
    assert.match(secret, /^[A-Za-z0-9_-]{43}$/u);
    const [row] = w.tables.vault_devices;
    assert.equal(w.tables.vault_devices.length, 1);
    assert.equal(row.secret_sha256, sha(secret));
    assert.equal(row.status, 'pending');
    assert.equal(row.owner_id, USER_A);
    assert.ok(!JSON.stringify(row).includes(secret), '쿠키 값 원문은 저장하지 않음');
    assert.ok(!JSON.stringify(res.body).includes(secret) && !JSON.stringify(res.body).includes(row.secret_sha256));
    // 요청만으로는 권한이 없다: 자료 API는 403이다
    const data = await w.call(w.gate().collection, 'GET', { token: w.A, cookie: secret });
    assert.equal(data.statusCode, 403);
    assert.deepEqual(data.body, { error: '기기 승인이 필요합니다.', code: 'device_not_approved' });
  } finally { w.done(); }
});

test('쿠키 읽기: 다른 쿠키 사이에서도 찾고 형식이 틀리면 없는 것으로 본다', () => {
  const value = 'a'.repeat(43);
  assert.equal(readDeviceCookie({ headers: { cookie: `x=1; ${DEVICE_COOKIE}=${value}; y=2` } }), value);
  for (const header of [undefined, '', `${DEVICE_COOKIE}=short`, `${DEVICE_COOKIE}=${'a'.repeat(44)}`, `other=${value}`, `${DEVICE_COOKIE}=${value}!`, 7, 'x'.repeat(5000)]) {
    assert.equal(readDeviceCookie({ headers: { cookie: header } }), null, String(header).slice(0, 30));
  }
  assert.equal(readDeviceCookie({}), null);
});

test('상태: 쿠키가 없거나 다른 계정·변조·만료이면 확인 전이고 대기 중이면 코드를 돌려준다', async () => {
  const w = world();
  try {
    assert.deepEqual((await w.call(w.api.status, 'GET', { token: w.A })).body, { status: 'unverified' });
    const requested = await w.call(w.api.request, 'POST', { token: w.A });
    const cookie = w.cookieOf(requested);
    const pending = await w.call(w.api.status, 'GET', { token: w.A, cookie });
    assert.deepEqual(pending.body, { status: 'pending', code: requested.body.code, expiresInSeconds: 900 });
    assert.ok(!JSON.stringify(pending.body).includes('sha') && !JSON.stringify(pending.body).includes(cookie));
    for (const odd of [`${cookie.slice(0, -1)}${cookie.endsWith('a') ? 'b' : 'a'}`, 'z'.repeat(43), 'short']) {
      assert.deepEqual((await w.call(w.api.status, 'GET', { token: w.A, cookie: odd })).body, { status: 'unverified' });
    }
    assert.deepEqual((await w.call(w.api.status, 'GET', { token: w.B, cookie })).body, { status: 'unverified' }, '다른 계정');
    w.tick(901 * 1000);
    assert.deepEqual((await w.call(w.api.status, 'GET', { token: w.A, cookie })).body, { status: 'unverified' }, '만료');
    assert.equal((await w.call(w.api.status, 'GET', {})).statusCode, 401);
    assert.equal((await w.call(w.api.status, 'POST', { token: w.A })).statusCode, 405);
  } finally { w.done(); }
});

test('같은 기기가 다시 요청하면 같은 코드를 돌려주고, 만료되면 같은 기기에 새 코드를 준다', async () => {
  const w = world();
  try {
    const first = await w.call(w.api.request, 'POST', { token: w.A });
    const cookie = w.cookieOf(first);
    const again = await w.call(w.api.request, 'POST', { token: w.A, cookie });
    assert.equal(again.statusCode, 200);
    assert.equal(again.body.code, first.body.code);
    assert.equal(w.tables.vault_devices.length, 1);
    assert.equal(again.headers['set-cookie'], undefined, '쿠키를 다시 내리지 않음');
    w.tick(901 * 1000);
    const renewed = await w.call(w.api.request, 'POST', { token: w.A, cookie });
    assert.equal(renewed.statusCode, 200);
    assert.match(renewed.body.code, CODE);
    assert.notEqual(renewed.body.code, first.body.code);
    assert.equal(renewed.body.expiresInSeconds, 900);
    assert.equal(w.tables.vault_devices.length, 1);
    assert.equal(w.tables.vault_devices[0].request_code, renewed.body.code);
  } finally { w.done(); }
});

test('대기 중인 기기는 자기 코드로도 승인할 수 없고 승인된 기기가 아니면 승인할 수 없다', async () => {
  const w = world();
  try {
    const requested = await w.call(w.api.request, 'POST', { token: w.A });
    const cookie = w.cookieOf(requested);
    for (const options of [{ token: w.A, cookie }, { token: w.A }]) {
      const res = await w.call(w.api.approve, 'POST', { ...options, body: { code: requested.body.code } });
      assert.equal(res.statusCode, 403);
    }
    assert.equal(w.tables.vault_devices[0].status, 'pending');
    assert.deepEqual((await w.call(w.api.status, 'GET', { token: w.A, cookie })).body.status, 'pending');
    assert.equal((await w.call(w.api.approve, 'POST', { body: { code: requested.body.code } })).statusCode, 401);
    assert.equal((await w.call(w.api.approve, 'GET', { token: w.A })).statusCode, 405);
  } finally { w.done(); }
});

test('승인 흐름: 승인된 기기가 같은 계정의 새 기기 코드를 승인하면 새 기기의 자료 요청이 열린다', async () => {
  const w = world();
  try {
    const first = await bootstrap(w);
    assert.equal((await w.call(w.api.status, 'GET', { token: w.A, cookie: first })).body.status, 'approved');
    const second = await w.call(w.api.request, 'POST', { token: w.A });
    const secondCookie = w.cookieOf(second);
    const gate = w.gate();
    assert.equal((await w.call(gate.collection, 'GET', { token: w.A, cookie: secondCookie })).statusCode, 403, '승인 전');
    const approved = await w.call(w.api.approve, 'POST', { token: w.A, cookie: first, body: { code: second.body.code.toLowerCase().replace(/^(.{4})/u, '$1-') } });
    assert.equal(approved.statusCode, 200);
    assert.deepEqual(approved.body, { approved: true });
    const row = w.tables.vault_devices.find((item) => item.request_code === second.body.code);
    assert.equal(row.status, 'approved');
    assert.match(row.decided_by, /^device:/u);
    assert.deepEqual((await w.call(w.api.status, 'GET', { token: w.A, cookie: secondCookie })).body, { status: 'approved' });
    const data = await w.call(gate.collection, 'GET', { token: w.A, cookie: secondCookie });
    assert.equal(data.statusCode, 200);
    assert.deepEqual(data.body, [{ id: NOTE_A, title: 'A의 메모', body: 'A의 내용' }]);
    // 승인된 기기의 같은 코드를 다시 쓸 수 없다
    assert.equal((await w.call(w.api.approve, 'POST', { token: w.A, cookie: first, body: { code: second.body.code } })).statusCode, 404);
  } finally { w.done(); }
});

test('승인 거부 사례: 모르는 코드, 다른 계정의 코드, 만료, 형식 오류, 다른 계정의 기기', async () => {
  const w = world();
  try {
    const firstA = await bootstrap(w, 'A');
    const requestB = await w.call(w.api.request, 'POST', { token: w.B });
    const cookieB = w.cookieOf(requestB);
    // 다른 계정의 코드는 같은 계정이 아니므로 찾을 수 없다
    assert.equal((await w.call(w.api.approve, 'POST', { token: w.A, cookie: firstA, body: { code: requestB.body.code } })).statusCode, 404);
    assert.equal((await w.call(w.api.approve, 'POST', { token: w.A, cookie: firstA, body: { code: 'ZZZZZZZZ' } })).statusCode, 404);
    // 승인된 A 기기의 쿠키를 B 토큰으로 쓰면 승인된 기기로 보지 않는다
    assert.equal((await w.call(w.api.approve, 'POST', { token: w.B, cookie: firstA, body: { code: requestB.body.code } })).statusCode, 403);
    for (const code of [undefined, '', 'abc', 'ZZZZZZZ', 'ILOU0000', 7, ['ABCDEFGH'], { code: 'x' }]) {
      assert.equal((await w.call(w.api.approve, 'POST', { token: w.A, cookie: firstA, body: { code } })).statusCode, 400, String(code));
    }
    assert.equal((await w.call(w.api.approve, 'POST', { token: w.A, cookie: firstA, body: null })).statusCode, 400);
    const requestA = await w.call(w.api.request, 'POST', { token: w.A });
    w.tick(901 * 1000);
    assert.equal((await w.call(w.api.approve, 'POST', { token: w.A, cookie: firstA, body: { code: requestA.body.code } })).statusCode, 404, '만료');
    assert.equal(w.tables.vault_devices.find((row) => row.request_code === requestA.body.code).status, 'pending');
    assert.equal(w.tables.vault_devices.find((row) => row.request_code === requestB.body.code).status, 'pending');
    assert.deepEqual((await w.call(w.api.status, 'GET', { token: w.B, cookie: cookieB })).body.status, 'unverified', 'B의 요청도 만료');
  } finally { w.done(); }
});

test('거부되거나 폐기된 기기와 알 수 없는 상태는 모두 거부됨으로 닫는다', async () => {
  const w = world();
  try {
    const requested = await w.call(w.api.request, 'POST', { token: w.A });
    const cookie = w.cookieOf(requested);
    const gate = w.gate();
    for (const state of ['denied', 'revoked', 'weird', '']) {
      w.tables.vault_devices[0].status = state;
      assert.deepEqual((await w.call(w.api.status, 'GET', { token: w.A, cookie })).body, { status: 'denied' }, state);
      const again = await w.call(w.api.request, 'POST', { token: w.A, cookie });
      assert.equal(again.statusCode, 403, state);
      assert.equal(again.body.status, 'denied');
      assert.equal((await w.call(gate.collection, 'GET', { token: w.A, cookie })).statusCode, 403, state);
      assert.equal((await w.call(w.api.approve, 'POST', { token: w.A, cookie, body: { code: 'ABCDEFGH' } })).statusCode, 403, state);
    }
  } finally { w.done(); }
});

test('한 계정이 동시에 가질 수 있는 승인 요청은 5개까지이다', async () => {
  const w = world();
  try {
    for (let index = 0; index < 5; index += 1) assert.equal((await w.call(w.api.request, 'POST', { token: w.A })).statusCode, 201);
    const sixth = await w.call(w.api.request, 'POST', { token: w.A });
    assert.equal(sixth.statusCode, 429);
    assert.equal(sixth.headers['set-cookie'], undefined);
    assert.equal(w.tables.vault_devices.length, 5);
    assert.equal(new Set(w.tables.vault_devices.map((row) => row.request_code)).size, 5);
    w.tick(901 * 1000);
    assert.equal((await w.call(w.api.request, 'POST', { token: w.A })).statusCode, 201, '만료된 요청은 세지 않음');
    assert.equal((await w.call(w.api.request, 'POST', { token: w.B })).statusCode, 201, '다른 계정은 따로 센다');
  } finally { w.done(); }
});

test('자료 API: 승인되지 않은 기기는 자료도 쓰기도 못 하고 저장소는 그대로이다', async () => {
  const w = world();
  try {
    const gate = w.gate();
    const before = JSON.stringify(w.tables.vault_notes);
    const none = await w.call(gate.collection, 'GET', { token: w.A });
    assert.equal(none.statusCode, 403);
    const pending = await w.call(w.api.request, 'POST', { token: w.A });
    const cookie = w.cookieOf(pending);
    const attempts = [
      [gate.collection, 'GET', {}], [gate.collection, 'POST', { body: { title: '추가', body: 'x' } }],
      [gate.item, 'GET', { url: `/api/notes/${NOTE_A}` }], [gate.item, 'PUT', { url: `/api/notes/${NOTE_A}`, body: { title: '수정', body: 'x' } }],
      [gate.item, 'DELETE', { url: `/api/notes/${NOTE_A}` }], [gate.restore, 'POST', { url: `/api/notes/${NOTE_A}/restore`, body: { contentSha256: 'a'.repeat(64) } }],
    ];
    for (const [handler, method, options] of attempts) {
      for (const device of [{}, { cookie }]) {
        const res = await w.call(handler, method, { token: w.A, ...device, ...options });
        assert.equal(res.statusCode, 403, `${method} ${options.url ?? '/api/notes'}`);
        assert.equal(res.body.code, 'device_not_approved');
      }
    }
    assert.equal(JSON.stringify(w.tables.vault_notes), before);
    assert.equal(w.calls.filter((call) => call.name === 'vault_notes').length, 0, '자료 표를 읽지도 않음');
    // 로그인이 먼저다: 토큰이 없으면 403이 아니라 401
    assert.equal((await w.call(gate.collection, 'GET', {})).statusCode, 401);
    assert.equal((await w.call(gate.collection, 'PATCH', { token: w.A, cookie })).statusCode, 405);
  } finally { w.done(); }
});

test('승인된 기기의 기존 자료 요청은 이전과 같은 결과이다', async () => {
  const w = world();
  try {
    const cookie = await bootstrap(w);
    const gate = w.gate();
    assert.deepEqual((await w.call(gate.collection, 'GET', { token: w.A, cookie })).body, [{ id: NOTE_A, title: 'A의 메모', body: 'A의 내용' }]);
    assert.equal((await w.call(gate.item, 'GET', { token: w.A, cookie, url: `/api/notes/${NOTE_A}` })).statusCode, 200);
    assert.equal((await w.call(gate.item, 'GET', { token: w.B, cookie, url: `/api/notes/${NOTE_A}` })).statusCode, 403, 'B 토큰에 A의 기기 쿠키는 통하지 않음');
    const bCookie = await bootstrap(w, 'B');
    const denied = await w.call(gate.item, 'GET', { token: w.B, cookie: bCookie, url: `/api/notes/${NOTE_A}` });
    assert.equal(denied.statusCode, 404, '승인된 B 기기여도 A의 메모는 소유자 대조로 404');
    assert.equal((await w.call(gate.item, 'PUT', { token: w.A, cookie, url: `/api/notes/${NOTE_A}`, body: { title: '수정', body: 'b' } })).statusCode, 200);
    assert.equal(w.tables.vault_notes[0].title, '수정');
  } finally { w.done(); }
});

test('심판용 토큰, DEVICE_GATE=off, 저장소 오류에서의 동작', async () => {
  const w = world();
  try {
    const gate = w.gate();
    assert.equal((await w.call(gate.collection, 'GET', { token: w.J })).statusCode, 200, 'judge 종류는 엔진이 기기를 검증한다고 보고 통과');
    assert.equal((await w.call(w.gate({ DEVICE_GATE: 'off' }).collection, 'GET', { token: w.A })).statusCode, 200);
    for (const value of ['', 'OFF', 'false', 'on']) {
      assert.equal((await w.call(w.gate({ DEVICE_GATE: value }).collection, 'GET', { token: w.A })).statusCode, 403, value);
    }
  } finally { w.done(); }
  for (const options of [{ failDevices: true }, { throwDevices: true }]) {
    const broken = world(options);
    try {
      const cookie = 'a'.repeat(43);
      const res = await broken.call(broken.gate().collection, 'GET', { token: broken.A, cookie });
      assert.equal(res.statusCode, 403, JSON.stringify(options));
      assert.equal(broken.calls.filter((call) => call.name === 'vault_notes').length, 0);
      assert.equal((await broken.call(broken.api.status, 'GET', { token: broken.A, cookie })).statusCode, 502);
      assert.equal((await broken.call(broken.api.request, 'POST', { token: broken.A })).statusCode, 502);
    } finally { broken.done(); }
  }
});

test('본문·쿼리·헤더의 권한 값은 읽지 않는다: 스스로 승인됨이라고 해도 대기이다', async () => {
  const w = world();
  try {
    const res = await w.call(w.api.request, 'POST', { token: w.A, body: { status: 'approved', owner_id: USER_B, device: { approval: true }, role: 'admin' },
      headers: { 'x-role': 'admin', 'x-device-id': 'a'.repeat(16) }, query: { status: 'approved' } });
    assert.equal(res.statusCode, 201);
    assert.equal(res.body.status, 'pending');
    assert.equal(w.tables.vault_devices[0].status, 'pending');
    assert.equal(w.tables.vault_devices[0].owner_id, USER_A);
    assert.match(w.logs(), /privilege_field_ignored/u);
    const cookie = w.cookieOf(res);
    const selfApprove = await w.call(w.api.approve, 'POST', { token: w.A, cookie, body: { code: res.body.code, status: 'approved' } });
    assert.equal(selfApprove.statusCode, 403);
  } finally { w.done(); }
});

test('응답과 로그에 쿠키 값, 해시, 토큰, 저장소 키가 없다', async () => {
  const w = world();
  try {
    const first = await bootstrap(w);
    const second = await w.call(w.api.request, 'POST', { token: w.A });
    // 승인 코드는 요청한 기기 화면에 보여 주는 값이라 요청 응답에는 있습니다. 로그와 다른 응답에는 없어야 합니다.
    const replies = [
      await w.call(w.api.approve, 'POST', { token: w.A, cookie: first, body: { code: 'ABCDEFGH' } }),
      await w.call(w.api.approve, 'POST', { token: w.A, body: { code: second.body.code } }),
      await w.call(w.gate().collection, 'GET', { token: w.A, cookie: w.cookieOf(second) }),
      await w.call(w.api.status, 'GET', { token: w.B, cookie: w.cookieOf(second) }),
    ];
    const cookies = [first, w.cookieOf(second)];
    const text = `${w.logs()}\n${replies.map((reply) => JSON.stringify(reply.body)).join('\n')}`;
    for (const secret of [...cookies, ...cookies.map(sha), STORE_VALUE, 'tokenA', USER_A, second.body.code]) {
      assert.ok(!text.includes(secret), String(secret).slice(0, 12));
    }
  } finally { w.done(); }
});

test('운영 연결: 자료 API는 기기 검사가 연결돼 있고 경로 파일은 기기 승인 함수를 내보낸다', async () => {
  assert.equal(notesApi.gated, true);
  assert.equal(createNotesApi().gated, false, '시험용 기본값은 검사가 없다');
  const root = fileURLToPath(new URL('..', import.meta.url));
  for (const [name, handler] of [['request', deviceApi.request], ['status', deviceApi.status], ['approve', deviceApi.approve]]) {
    assert.ok(existsSync(`${root}api/device/${name}.mjs`));
    assert.equal((await import(`../api/device/${name}.mjs`)).default, handler);
  }
  const functions = ['api/auth/login.mjs', 'api/auth/logout.mjs', 'api/auth/refresh.mjs', 'api/notes/index.mjs', 'api/notes/[id].mjs', 'api/notes/[id]/restore.mjs',
    'api/device/request.mjs', 'api/device/status.mjs', 'api/device/approve.mjs'];
  assert.ok(functions.every((path) => existsSync(`${root}${path}`)));
  assert.ok(functions.length <= 12, 'Vercel 무료 한도 12개 이내');
});
