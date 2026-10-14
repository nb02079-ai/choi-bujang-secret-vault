import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { createNotesApi } from '../src/notes-api.mjs';

const USER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOTE_A = '11111111-1111-4111-8111-111111111111';
const NOTE_B = '22222222-2222-4222-8222-222222222222';
const NOTE_NONE = '33333333-3333-4333-8333-333333333333';
// 키 모양 가짜 값은 실행할 때 조립해 저장소 파일에 키 형태 문자열이 남지 않게 합니다.
const STORE_VALUE = [['sb', ['sec', 'ret'].join(''), ''].join('_'), 'recheck_value'].join('');

function fakeResponse() {
  const res = { headers: {}, statusCode: 0, body: undefined };
  res.setHeader = (key, value) => { res.headers[key.toLowerCase()] = value; };
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (body) => { res.body = body; return res; };
  return res;
}

// ignoreOwnerFilter가 true이면 저장소가 owner_id 조건을 어기고 모든 행을 돌려주는 상황을 흉내 냅니다.
function memoryStore({ ignoreOwnerFilter = false } = {}) {
  const rows = [
    { id: NOTE_A, owner_id: USER_A, title: 'A의 메모', content: 'a' },
    { id: NOTE_B, owner_id: USER_B, title: 'B의 메모', content: 'b' },
    { id: NOTE_NONE, owner_id: null, title: '주인 없음', content: 'x' },
  ];
  const calls = [];
  const pick = (row, select) => Object.fromEntries(select.split(',').map(key => [key, row[key]]));
  const fetchImpl = async (url, init) => {
    const query = Object.fromEntries(url.searchParams);
    const eq = field => (query[field]?.startsWith('eq.') ? query[field].slice(3) : undefined);
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method: init.method, query, body });
    const matching = () => rows.filter(row => (eq('id') === undefined || row.id === eq('id'))
      && (ignoreOwnerFilter || eq('owner_id') === undefined || row.owner_id === eq('owner_id')));
    if (init.method === 'GET') return Response.json(matching().map(row => pick(row, query.select)));
    if (init.method === 'POST') {
      const row = { id: body.id ?? crypto.randomUUID(), ...body };
      rows.push(row);
      return Response.json([pick(row, query.select)], { status: 201 });
    }
    if (init.method === 'PATCH') {
      const hit = matching();
      hit.forEach(row => Object.assign(row, body));
      return Response.json(hit.map(row => pick(row, query.select)));
    }
    const hit = matching();
    hit.forEach(row => rows.splice(rows.indexOf(row), 1));
    return Response.json(hit.map(row => pick(row, query.select)));
  };
  return { rows, calls, fetchImpl };
}

function fixture(options) {
  const store = memoryStore(options);
  const tokens = {
    'Bearer tokenA.aaa.aaa': { kind: 'student', userId: USER_A },
    'Bearer tokenB.bbb.bbb': { kind: 'student', userId: USER_B },
    'Bearer judgeB.bbb.bbb': { kind: 'judge', userId: USER_B, runId: 'run', identity: 'b' },
  };
  const api = createNotesApi({ verify: async authorization => tokens[authorization] ?? null,
    fetchImpl: store.fetchImpl,
    env: { SUPABASE_URL: 'https://example-project.supabase.co', SUPABASE_SECRET_KEY: STORE_VALUE } });
  const call = async (handler, method, { token, url = '/api/notes', body, headers = {}, query } = {}) => {
    const res = fakeResponse();
    const authorization = token ? { authorization: `Bearer ${token}` } : {};
    await handler({ method, url, query, headers: { ...authorization, ...headers }, body }, res);
    return res;
  };
  const warnings = mock.method(console, 'warn', () => {});
  const lines = () => warnings.mock.calls.map(entry => entry.arguments.join(' '));
  return { api, store, call, lines, A: 'tokenA.aaa.aaa', B: 'tokenB.bbb.bbb', J: 'judgeB.bbb.bbb',
    restore: () => warnings.mock.restore() };
}

test('직접 요청으로 남의 메모를 읽거나 고치거나 지울 수 없고 저장소는 그대로다', async () => {
  const f = fixture();
  try {
    const before = JSON.stringify(f.store.rows);
    for (const [token, target] of [[f.B, NOTE_A], [f.A, NOTE_B], [f.A, NOTE_NONE], [f.B, NOTE_NONE]]) {
      const url = `/api/notes/${target}`;
      for (const [method, body] of [['GET'], ['PUT', { title: '탈취', body: 'x' }], ['DELETE']]) {
        const res = await f.call(f.api.item, method, { token, url, body });
        assert.equal(res.statusCode, 404, `${method} ${target}`);
        assert.deepEqual(res.body, { error: '메모를 찾을 수 없습니다.' });
      }
    }
    assert.equal(JSON.stringify(f.store.rows), before);
    const joined = f.lines().join('\n');
    assert.match(joined, /not_owner/u);
    assert.match(joined, /no_owner/u);
  } finally { f.restore(); }
});

test('저장소가 조건을 어겨도 목록에는 내 메모만 나온다', async () => {
  const f = fixture({ ignoreOwnerFilter: true });
  try {
    const listB = await f.call(f.api.collection, 'GET', { token: f.B });
    assert.equal(listB.statusCode, 200);
    assert.deepEqual(listB.body.map(note => note.id), [NOTE_B]);
    assert.doesNotMatch(JSON.stringify(listB.body), /owner_id/u);
    const listA = await f.call(f.api.collection, 'GET', { token: f.A });
    assert.deepEqual(listA.body.map(note => note.id), [NOTE_A]);
    assert.ok(f.lines().some(line => /owner_mismatch GET/u.test(line)));
  } finally { f.restore(); }
});

test('주인 없는 행은 목록에 나오지 않는다', async () => {
  const f = fixture({ ignoreOwnerFilter: true });
  try {
    const list = await f.call(f.api.collection, 'GET', { token: f.A });
    assert.equal(list.body.some(note => note.id === NOTE_NONE), false);
  } finally { f.restore(); }
});

test('본문·쿼리·헤더의 role과 owner_id는 권한이 되지 않고 사유만 기록된다', async () => {
  const f = fixture();
  try {
    const spoof = { 'x-role': 'instructor', 'x-user-id': USER_A, 'x-owner-id': USER_A };
    const url = `/api/notes/${NOTE_A}`;
    const read = await f.call(f.api.item, 'GET', { token: f.B, url, headers: spoof, query: { role: 'instructor', zone: 'notice' } });
    assert.equal(read.statusCode, 404);
    const write = await f.call(f.api.item, 'PUT', { token: f.B, url,
      body: { title: '탈취', body: 'x', role: 'instructor', is_instructor: true, zone: 'instructor' } });
    assert.equal(write.statusCode, 404);
    const del = await f.call(f.api.item, 'DELETE', { token: f.B, url, headers: spoof });
    assert.equal(del.statusCode, 404);
    const list = await f.call(f.api.collection, 'GET', { token: f.B, headers: spoof, query: { owner_id: USER_A, role: 'instructor' } });
    assert.deepEqual(list.body.map(note => note.id), [NOTE_B]);
    const created = await f.call(f.api.collection, 'POST', { token: f.B,
      body: { title: '새 메모', body: 'n', role: 'instructor', owner_id: USER_A, userId: USER_A } });
    assert.equal(created.statusCode, 201);
    assert.equal(f.store.rows.find(row => row.id === created.body.id).owner_id, USER_B);
    assert.equal(f.store.rows.find(row => row.id === created.body.id).role, undefined);
    assert.equal(f.store.rows.find(row => row.id === NOTE_A).title, 'A의 메모');
    assert.ok(f.lines().filter(line => /privilege_field_ignored/u.test(line)).length >= 5);
  } finally { f.restore(); }
});

test('소유자를 바꾸려는 수정은 403이고 사유가 남는다', async () => {
  const f = fixture();
  try {
    const before = JSON.stringify(f.store.rows);
    const res = await f.call(f.api.item, 'PUT', { token: f.A, url: `/api/notes/${NOTE_A}`,
      body: { title: '이전', body: 'x', owner_id: USER_B } });
    assert.equal(res.statusCode, 403);
    assert.equal(JSON.stringify(f.store.rows), before);
    assert.ok(f.lines().some(line => /owner_change_attempt PUT/u.test(line)));
  } finally { f.restore(); }
});

test('확인과 쓰기 사이에 소유자가 바뀌면 쓰지 않고 owner_changed를 남긴다', async () => {
  const f = fixture();
  try {
    const original = f.store.fetchImpl;
    let first = true;
    const api = createNotesApi({
      verify: async () => ({ kind: 'student', userId: USER_A }),
      env: { SUPABASE_URL: 'https://example-project.supabase.co', SUPABASE_SECRET_KEY: STORE_VALUE },
      fetchImpl: async (url, init) => {
        const response = await original(url, init);
        if (first && init.method === 'GET') { first = false; f.store.rows.find(row => row.id === NOTE_A).owner_id = USER_B; }
        return response;
      },
    });
    const res = fakeResponse();
    await api.item({ method: 'DELETE', url: `/api/notes/${NOTE_A}`, headers: { authorization: 'Bearer tokenA.aaa.aaa' } }, res);
    assert.equal(res.statusCode, 404);
    assert.equal(f.store.rows.some(row => row.id === NOTE_A), true, '남의 행은 지워지지 않음');
    assert.ok(f.lines().some(line => /owner_changed DELETE/u.test(line)));
  } finally { f.restore(); }
});

test('판정자 토큰도 자기 userId의 메모만 다룬다', async () => {
  const f = fixture({ ignoreOwnerFilter: true });
  try {
    const list = await f.call(f.api.collection, 'GET', { token: f.J });
    assert.deepEqual(list.body.map(note => note.id), [NOTE_B]);
    assert.equal((await f.call(f.api.item, 'GET', { token: f.J, url: `/api/notes/${NOTE_A}` })).statusCode, 404);
  } finally { f.restore(); }
});

test('거부 사유 기록에는 ID, 토큰, 본문이 들어 있지 않다', async () => {
  const f = fixture();
  try {
    await f.call(f.api.item, 'PUT', { token: f.B, url: `/api/notes/${NOTE_A}`,
      body: { title: '비밀 제목', body: '비밀 내용', role: 'instructor' } });
    await f.call(f.api.item, 'GET', { token: f.B, url: '/api/notes/not-a-uuid' });
    const joined = f.lines().join('\n');
    assert.ok(joined.length > 0);
    for (const secret of [USER_A, USER_B, NOTE_A, 'tokenB', '비밀 제목', '비밀 내용', STORE_VALUE]) {
      assert.equal(joined.includes(secret), false, secret);
    }
    assert.match(joined, /bad_id GET/u);
  } finally { f.restore(); }
});

test('강사라고 주장해도 구역 밖 경로는 처리되지 않고 저장소를 부르지 않는다', async () => {
  const f = fixture();
  try {
    const before = f.store.calls.length;
    for (const method of ['POST', 'PATCH', 'DELETE']) {
      const res = await f.call(f.api.item, method, { token: f.B, url: `/api/notes/${NOTE_A}/export`,
        headers: { 'x-role': 'instructor' }, body: { title: 't', body: 'b' } });
      assert.ok([404, 405].includes(res.statusCode), `${method} ${res.statusCode}`);
    }
    assert.equal(f.store.calls.length, before);
  } finally { f.restore(); }
});
