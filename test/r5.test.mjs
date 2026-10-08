import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('first attack check reads public data.json without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/data.json');
    assert.equal(options.redirect, 'error');
    assert.match(result.observed, /확인 표시가 보임/u);
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /보이지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('deployment identity keeps the configured step', () => {
  assert.equal(deploymentIdentity(env, { ...config, step: 2 }).step, 2);
  assert.equal(deploymentIdentity(env, { ...config, step: 3 }).step, 3);
  assert.throws(() => deploymentIdentity(env, { ...config, step: 13 }));
});

test('step 2 attack check records only requests it sent', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  try {
    globalThis.fetch = async (url, init = {}) => {
      const path = new URL(String(url)).pathname;
      calls.push(`${init.method ?? 'GET'} ${path}`);
      if (path === '/data.json') return Response.json({ notes: [] });
      if (init.method === 'POST') return new Response('no', { status: 405 });
      return Response.json({ notes: [{ title: 'a', content: 'b' }] });
    };
    const results = await runAttackChecks({ ...config, step: 2 });
    assert.deepEqual(calls, ['GET /data.json', 'GET /api/notes', 'POST /api/notes']);
    const byId = Object.fromEntries(results.map(item => [item.attackId, item.observed]));
    assert.match(byId.static_data_json_empty, /비어 있고/u);
    assert.match(byId.anonymous_api_read, /1건이 읽힘/u);
    assert.match(byId.api_response_no_key, /없음/u);
    assert.match(byId.api_post_rejected, /405/u);
    for (const item of results) {
      assert.deepEqual(Object.keys(item).sort(), ['attackId', 'expected', 'observed']);
      assert.doesNotMatch(JSON.stringify(item), /"title"|"content"/u);
    }
    assert.match(byId.static_data_json_empty, /확인 표시가 없음/u);
    globalThis.fetch = async (url) => (new URL(String(url)).pathname === '/data.json'
      ? Response.json({ sampleMarker: 'SAMPLE_NOTE_1', notes: [] })
      : Response.json({ notes: [] }));
    const marked = await runAttackChecks({ ...config, step: 2 });
    assert.match(marked.find(item => item.attackId === 'static_data_json_empty').observed, /확인 표시가 남아 있음/u);
    globalThis.fetch = async () => { throw new Error('network'); };
    const failed = await runAttackChecks({ ...config, step: 2 });
    assert.equal(failed.length, 4);
    assert.ok(failed.every(item => /확인하지 못함/u.test(item.observed)));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

function fakeResponse() {
  const res = { headers: {}, statusCode: 0, body: undefined };
  res.setHeader = (key, value) => { res.headers[key.toLowerCase()] = value; };
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (body) => { res.body = body; return res; };
  return res;
}

const USER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const SECRET = 'sb_secret_testvalue_never_returned';

// 자료 저장소(PostgREST)를 흉내 내는 메모리 저장소입니다. 실제 Supabase를 부르지 않습니다.
function memoryStore() {
  const rows = [];
  const calls = [];
  const pick = (row, select) => Object.fromEntries(select.split(',').map(key => [key, row[key]]));
  const fetchImpl = async (url, init) => {
    assert.equal(init.headers.apikey, SECRET);
    const query = Object.fromEntries(url.searchParams);
    const eq = (field) => (query[field]?.startsWith('eq.') ? query[field].slice(3) : undefined);
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method: init.method, query, body });
    const matching = () => rows.filter(row => (eq('id') === undefined || row.id === eq('id'))
      && (eq('owner_id') === undefined || row.owner_id === eq('owner_id')));
    if (init.method === 'GET') return Response.json(matching().map(row => pick(row, query.select)));
    if (init.method === 'POST') {
      const row = { id: body.id ?? crypto.randomUUID(), ...body };
      if (rows.some(existing => existing.id === row.id)) return new Response('{}', { status: 409 });
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

async function notesFixture() {
  const { createNotesApi } = await import('../src/notes-api.mjs');
  const store = memoryStore();
  const tokens = {
    'Bearer tokenA.aaa.aaa': { kind: 'student', userId: USER_A },
    'Bearer tokenB.bbb.bbb': { kind: 'student', userId: USER_B },
  };
  const verify = async (authorization) => tokens[authorization] ?? null;
  const api = createNotesApi({ verify, fetchImpl: store.fetchImpl,
    env: { SUPABASE_URL: 'https://example-project.supabase.co', SUPABASE_SECRET_KEY: SECRET } });
  const call = async (handler, method, { token, url = '/api/notes', body, headers = {} } = {}) => {
    const res = fakeResponse();
    const authorization = token ? { authorization: `Bearer ${token}` } : {};
    await handler({ method, url, headers: { ...authorization, ...headers }, body }, res);
    return res;
  };
  return { api, store, call, A: 'tokenA.aaa.aaa', B: 'tokenB.bbb.bbb' };
}

test('notes api rejects every route without a verified login and never touches the store', async () => {
  const { api, store, call, A } = await notesFixture();
  const id = '11111111-1111-4111-8111-111111111111';
  const spoof = { 'x-user-id': USER_A, 'x-role': 'admin' };
  const routes = [[api.collection, 'GET', '/api/notes'], [api.collection, 'POST', '/api/notes'],
    [api.item, 'GET', `/api/notes/${id}`], [api.item, 'PUT', `/api/notes/${id}`], [api.item, 'DELETE', `/api/notes/${id}`]];
  for (const [handler, method, url] of routes) {
    for (const extra of [{}, { token: 'bad.token.value' }]) {
      const res = await call(handler, method, { url, headers: spoof, body: { title: 't', body: 'b', owner_id: USER_A }, ...extra });
      assert.equal(res.statusCode, 401, `${method} ${url}`);
      assert.deepEqual(res.body, { error: '로그인이 필요합니다.' });
    }
  }
  assert.equal(store.calls.length, 0);
  assert.equal((await call(api.collection, 'DELETE', { token: A })).statusCode, 405);
  assert.equal((await call(api.item, 'POST', { token: A, url: `/api/notes/${id}` })).statusCode, 405);
});

test('notes api lets a logged-in user add, read, edit and delete notes', async () => {
  const { api, store, call, A, B } = await notesFixture();

  const created = await call(api.collection, 'POST', { token: A,
    body: { title: '  첫 메모 ', body: '내용', owner_id: USER_B, userId: USER_B, role: 'admin' } });
  assert.equal(created.statusCode, 201);
  const id = created.body.id;
  assert.match(id, /^[0-9a-f-]{36}$/u);
  assert.deepEqual(Object.keys(created.body), ['id']);
  assert.equal(store.rows[0].owner_id, USER_A, '저장되는 owner_id는 서버가 확인한 사용자 ID여야 함');
  assert.equal(store.rows[0].title, '첫 메모');
  assert.equal(store.rows[0].role, undefined);
  assert.equal(store.rows[0].userId, undefined);

  const givenId = '22222222-2222-4222-8222-222222222222';
  const withId = await call(api.collection, 'POST', { token: A, body: { id: givenId, title: '둘째', body: '' } });
  assert.deepEqual(withId.body, { id: givenId });
  assert.equal((await call(api.collection, 'POST', { token: A, body: { id: givenId, title: 'x', body: '' } })).statusCode, 409);
  assert.equal((await call(api.collection, 'POST', { token: A, body: { id: 'not-a-uuid', title: 'x', body: '' } })).statusCode, 400);
  const invalid = [{}, { title: '' }, { title: '   ' }, { title: 5 }, { title: 'x'.repeat(101) },
    { title: 't', body: 7 }, { title: 't', body: 'x'.repeat(2001) }, []];
  for (const bad of invalid) {
    assert.equal((await call(api.collection, 'POST', { token: A, body: bad })).statusCode, 400, JSON.stringify(bad));
  }

  await call(api.collection, 'POST', { token: B, body: { title: 'B의 메모', body: 'b' } });
  const list = await call(api.collection, 'GET', { token: A });
  assert.equal(list.statusCode, 200);
  assert.ok(Array.isArray(list.body));
  assert.deepEqual(list.body.map(note => note.title), ['첫 메모', '둘째']);
  assert.deepEqual(Object.keys(list.body[0]).sort(), ['body', 'id', 'title']);
  assert.doesNotMatch(JSON.stringify(list.body), /owner_id/u);

  const itemUrl = `/api/notes/${id}`;
  const one = await call(api.item, 'GET', { token: A, url: itemUrl });
  assert.deepEqual(one.body, { id, title: '첫 메모', body: '내용' });

  const edited = await call(api.item, 'PUT', { token: A, url: itemUrl, body: { title: '고친 제목', body: '고친 내용', owner_id: USER_A } });
  assert.equal(edited.statusCode, 200);
  assert.deepEqual(edited.body, { id });
  assert.equal(store.rows.find(row => row.id === id).owner_id, USER_A, '수정해도 owner_id는 바뀌지 않음');
  assert.deepEqual((await call(api.item, 'GET', { token: A, url: itemUrl })).body, { id, title: '고친 제목', body: '고친 내용' });
  assert.equal((await call(api.item, 'PUT', { token: A, url: itemUrl, body: { id: givenId, title: 't', body: '' } })).statusCode, 400);

  assert.equal((await call(api.item, 'DELETE', { token: A, url: itemUrl })).statusCode, 200);
  assert.equal((await call(api.item, 'GET', { token: A, url: itemUrl })).statusCode, 404);
  assert.equal((await call(api.item, 'DELETE', { token: A, url: itemUrl })).statusCode, 404);
  assert.equal((await call(api.item, 'PUT', { token: A, url: itemUrl, body: { title: 't', body: '' } })).statusCode, 404);
  const before = store.calls.length;
  assert.equal((await call(api.item, 'GET', { token: A, url: '/api/notes/not-a-uuid' })).statusCode, 404);
  assert.equal(store.calls.length, before, '형식이 틀린 id는 저장소를 부르지 않음');

  assert.doesNotMatch(JSON.stringify([list.body, created.body, one.body]), new RegExp(SECRET, 'u'));
});

test('notes api limits read, add, edit and delete to the verified owner', async () => {
  const { api, store, call, A, B } = await notesFixture();
  const snapshot = () => JSON.stringify(store.rows);

  // A와 B가 각자 메모를 만듭니다. 본문의 owner_id는 무시되고 확인된 사용자 ID로 저장됩니다.
  const a1 = (await call(api.collection, 'POST', { token: A, body: { title: 'A의 메모', body: 'a', owner_id: USER_B } })).body.id;
  const b1 = (await call(api.collection, 'POST', { token: B, body: { title: 'B의 메모', body: 'b', owner_id: USER_A } })).body.id;
  assert.equal(store.rows.find(row => row.id === a1).owner_id, USER_A);
  assert.equal(store.rows.find(row => row.id === b1).owner_id, USER_B);
  // 주인이 없는 기존 메모(처음 네 건 중 하나)는 누구도 접근할 수 없습니다.
  store.rows.push({ id: '33333333-3333-4333-8333-333333333333', owner_id: null, title: '주인 없음', content: 'x' });
  const orphan = '33333333-3333-4333-8333-333333333333';

  // 각자 자기 메모는 읽고 고치고 지울 수 있습니다.
  assert.deepEqual((await call(api.item, 'GET', { token: A, url: `/api/notes/${a1}` })).body, { id: a1, title: 'A의 메모', body: 'a' });
  assert.deepEqual((await call(api.item, 'GET', { token: B, url: `/api/notes/${b1}` })).body, { id: b1, title: 'B의 메모', body: 'b' });
  assert.equal((await call(api.item, 'PUT', { token: B, url: `/api/notes/${b1}`, body: { title: 'B 수정', body: 'b2', owner_id: USER_B } })).statusCode, 200);

  // 목록에는 본인 메모만 나옵니다. 쿼리의 owner_id도 쓰지 않습니다.
  assert.deepEqual((await call(api.collection, 'GET', { token: A, url: `/api/notes?owner_id=${USER_B}` })).body.map(note => note.id), [a1]);
  assert.deepEqual((await call(api.collection, 'GET', { token: B })).body.map(note => note.id), [b1]);

  // 상대 메모와 주인 없는 메모는 읽기·수정·삭제 모두 404이고 저장소의 값은 바뀌지 않습니다.
  const before = snapshot();
  for (const [token, target] of [[B, a1], [A, b1], [A, orphan], [B, orphan]]) {
    const url = `/api/notes/${target}`;
    assert.equal((await call(api.item, 'GET', { token, url })).statusCode, 404, `GET ${target}`);
    assert.equal((await call(api.item, 'PUT', { token, url, body: { title: '탈취', body: 'x' } })).statusCode, 404, `PUT ${target}`);
    assert.equal((await call(api.item, 'DELETE', { token, url })).statusCode, 404, `DELETE ${target}`);
    // 본인 ID를 owner_id로 내세워 남의 메모를 가져오려는 시도도 거부됩니다.
    const self = token === A ? USER_A : USER_B;
    assert.equal((await call(api.item, 'PUT', { token, url, body: { title: '탈취', body: 'x', owner_id: self } })).statusCode, 404);
  }
  assert.equal(snapshot(), before);

  // 내 메모의 소유자를 바꾸려는 수정은 쓰기 전에 거부됩니다.
  for (const owner of [USER_B, null, 7, '', 'not-a-uuid']) {
    const res = await call(api.item, 'PUT', { token: A, url: `/api/notes/${a1}`, body: { title: '이전', body: 'x', owner_id: owner } });
    assert.equal(res.statusCode, 403, JSON.stringify(owner));
  }
  assert.equal(snapshot(), before);
  assert.equal(store.rows.find(row => row.id === a1).owner_id, USER_A);

  // 저장소에 보내는 수정·삭제에는 항상 본인 owner_id 조건이 붙고, 수정 값의 owner_id도 본인입니다.
  const writes = store.calls.filter(entry => ['PATCH', 'DELETE'].includes(entry.method));
  assert.ok(writes.length > 0);
  for (const write of writes) {
    assert.match(write.query.owner_id, /^eq\.(a{8}-a{4}-4a{3}-8a{3}-a{12}|b{8}-b{4}-4b{3}-8b{3}-b{12})$/u);
    if (write.body) assert.equal(write.body.owner_id, write.query.owner_id.slice(3));
  }

  // 본인 메모 삭제는 되고, 지운 뒤에는 404이며, 남의 메모는 그대로 남습니다.
  assert.equal((await call(api.item, 'DELETE', { token: A, url: `/api/notes/${a1}` })).statusCode, 200);
  assert.equal((await call(api.item, 'GET', { token: A, url: `/api/notes/${a1}` })).statusCode, 404);
  assert.equal(store.rows.some(row => row.id === b1), true);
  assert.equal((await call(api.item, 'DELETE', { token: B, url: `/api/notes/${b1}` })).statusCode, 200);
});

test('allowedRoutes lists exactly the routes the handlers accept', async () => {
  const { readFileSync } = await import('node:fs');
  const real = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
  const { api, call, A } = await notesFixture();
  const id = '44444444-4444-4444-8444-444444444444';
  const accepted = [];
  for (const [handler, path, shape] of [[api.collection, '/api/notes', '/api/notes'], [api.item, `/api/notes/${id}`, '/api/notes/:id']]) {
    for (const method of ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']) {
      const res = await call(handler, method, { token: A, url: path, body: { title: 't', body: 'b' } });
      if (res.statusCode !== 405) accepted.push(`${method} ${shape}`);
    }
  }
  assert.deepEqual([...accepted].sort(), [...real.allowedRoutes].sort());
});

test('notes api reports server setup problems without leaking the key', async () => {
  const { createNotesApi } = await import('../src/notes-api.mjs');
  const env = { SUPABASE_URL: 'https://example-project.supabase.co', SUPABASE_SECRET_KEY: SECRET };
  const request = { method: 'GET', url: '/api/notes', headers: { authorization: 'Bearer a.b.c' } };
  const broken = createNotesApi({ env, verify: async () => { throw new TypeError('invalid_student_identity_provider'); },
    fetchImpl: async () => { throw new Error('no'); } });
  const res = fakeResponse();
  await broken.collection(request, res);
  assert.equal(res.statusCode, 500);
  const missing = createNotesApi({ env: {}, verify: async () => ({ userId: USER_A }) });
  const none = fakeResponse();
  await missing.collection(request, none);
  assert.equal(none.statusCode, 500);
  const down = createNotesApi({ env, verify: async () => ({ userId: USER_A }), fetchImpl: async () => { throw new Error('boom'); } });
  const bad = fakeResponse();
  await down.collection(request, bad);
  assert.equal(bad.statusCode, 502);
  assert.doesNotMatch(JSON.stringify([res.body, none.body, bad.body]), new RegExp(SECRET, 'u'));
});

test('aleph.config.json identityProvider is accepted by the starter login verifier', async () => {
  const { createLoginVerifier } = await import('../src/verify-login.mjs');
  const { readFileSync } = await import('node:fs');
  const real = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
  const verifier = createLoginVerifier({ config: real, supabaseClient: { auth: { getClaims: async () => ({ error: new Error('x') }) } } });
  assert.equal(await verifier(undefined), null);
  assert.equal(await verifier('Bearer aaa.bbb.ccc'), null);
  assert.equal(real.identityProvider.audience, 'authenticated');
  assert.equal(real.identityProvider.jwksUrl, `${real.identityProvider.issuer}/.well-known/jwks.json`);
  assert.doesNotMatch(JSON.stringify(real.identityProvider), /secret|service_role|eyJ/iu);
});

test('step 3 attack check sends tokenless requests and leaves account checks unrun', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  try {
    globalThis.fetch = async (url, init = {}) => {
      const { pathname } = new URL(String(url));
      const method = init.method ?? 'GET';
      calls.push(`${method} ${pathname}`);
      assert.equal(init.headers?.Authorization === undefined || init.headers.Authorization === 'Bearer aaa.bbb.ccc', true);
      if (pathname === '/data.json') return Response.json({ notes: [] });
      if (method === 'PATCH') return new Response('no', { status: 405 });
      return Response.json({ error: '로그인이 필요합니다.' }, { status: 401 });
    };
    const results = await runAttackChecks({ ...config, step: 3 });
    assert.deepEqual(calls, ['GET /data.json', 'GET /api/notes', 'POST /api/notes',
      'GET /api/notes/00000000-0000-4000-8000-000000000000', 'PUT /api/notes/00000000-0000-4000-8000-000000000000',
      'DELETE /api/notes/00000000-0000-4000-8000-000000000000', 'GET /api/notes', 'POST /api/notes', 'PATCH /api/notes']);
    const byId = Object.fromEntries(results.map(item => [item.attackId, item.observed]));
    assert.match(byId.static_data_json_empty, /비어 있고/u);
    for (const id of ['anonymous_list_rejected', 'anonymous_create_rejected', 'anonymous_get_one_rejected',
      'anonymous_update_rejected', 'anonymous_delete_rejected', 'forged_token_rejected', 'forged_identity_rejected']) {
      assert.equal(byId[id], '거부됨 (HTTP 401)', id);
    }
    assert.equal(byId.unsupported_method_rejected, '거부됨 (HTTP 405)');
    assert.match(byId.logged_in_crud, /^미실행/u);
    assert.match(byId.cross_user_access, /^미실행/u);
    assert.equal(new Set(results.map(item => item.attackId)).size, results.length);
    for (const item of results) assert.deepEqual(Object.keys(item).sort(), ['attackId', 'expected', 'observed']);

    globalThis.fetch = async (url) => (new URL(String(url)).pathname === '/data.json'
      ? Response.json({ notes: [] })
      : Response.json({ notes: [{ title: 't' }], leak: 'sb_secret_abcdef123456' }, { status: 200 }));
    const open = Object.fromEntries((await runAttackChecks({ ...config, step: 3 })).map(item => [item.attackId, item.observed]));
    assert.match(open.anonymous_list_rejected, /401이 아닌 응답이 옴 \(HTTP 200\)\. 응답에 비밀키 형태/u);
    assert.match(open.anonymous_delete_rejected, /401이 아닌 응답이 옴/u);

    globalThis.fetch = async () => { throw new Error('network'); };
    const down = await runAttackChecks({ ...config, step: 3 });
    assert.equal(down.filter(item => /확인하지 못함/u.test(item.observed)).length, 9);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 4 attack check probes the Data API with the public anon key only', async () => {
  const originalFetch = globalThis.fetch;
  const key = 'sb_publishable_abcdefghij1234567890';
  const step4 = { ...config, step: 4, identityProvider: { issuer: 'https://projref.supabase.co/auth/v1' } };
  const seen = [];
  const handler = (dataApiStatus, pageHtml) => async (url, init = {}) => {
    const target = new URL(String(url));
    const method = init.method ?? 'GET';
    seen.push({ host: target.host, method, path: target.pathname, search: target.search, apikey: init.headers?.apikey, body: init.body });
    if (target.host === 'projref.supabase.co') return Response.json({ code: '42501' }, { status: dataApiStatus });
    if (target.pathname === '/' ) return new Response(pageHtml, { status: 200 });
    if (target.pathname === '/data.json') return Response.json({ notes: [] });
    if (method === 'PATCH') return new Response('no', { status: 405 });
    return Response.json({ error: '로그인이 필요합니다.' }, { status: 401 });
  };
  try {
    globalThis.fetch = handler(401, `<script>createClient('x', '${key}')</script>`);
    const results = await runAttackChecks(step4);
    const byId = Object.fromEntries(results.map(item => [item.attackId, item.observed]));
    for (const id of ['anon_direct_read_rejected', 'anon_direct_create_rejected',
      'anon_direct_update_rejected', 'anon_direct_delete_rejected']) {
      assert.equal(byId[id], '거부됨 (HTTP 401)', id);
    }
    const direct = seen.filter(entry => entry.host === 'projref.supabase.co');
    assert.deepEqual(direct.map(entry => entry.method), ['GET', 'POST', 'PATCH', 'DELETE']);
    assert.ok(direct.every(entry => entry.path === '/rest/v1/vault_notes' && entry.apikey === key));
    assert.equal(direct[1].body, '{}', '추가 점검은 필수 칸이 빠진 빈 본문만 보냄');
    for (const entry of direct.slice(2)) assert.match(entry.search, /^\?id=eq\.00000000-0000-4000-8000-000000000000$/u);
    assert.match(byId.logged_in_own_crud, /^미실행/u);
    assert.match(byId.cross_user_access, /^미실행/u);
    assert.equal(byId.logged_in_crud, undefined);
    assert.ok(results.length <= 20);
    assert.equal(new Set(results.map(item => item.attackId)).size, results.length);
    assert.doesNotMatch(JSON.stringify(results), new RegExp(key, 'u'), '결과에 공개 키도 싣지 않음');
    for (const item of results) assert.deepEqual(Object.keys(item).sort(), ['attackId', 'expected', 'observed']);

    seen.length = 0;
    globalThis.fetch = handler(200, `<script>'${key}'</script>`);
    const open = Object.fromEntries((await runAttackChecks(step4)).map(item => [item.attackId, item.observed]));
    assert.match(open.anon_direct_read_rejected, /401\/403이 아닌 응답이 옴 \(HTTP 200\)/u);
    assert.match(open.anon_direct_delete_rejected, /401\/403이 아닌 응답이 옴/u);

    seen.length = 0;
    globalThis.fetch = handler(401, '<html>키 없음</html>');
    const nokey = Object.fromEntries((await runAttackChecks(step4)).map(item => [item.attackId, item.observed]));
    assert.match(nokey.anon_direct_read_rejected, /^미실행/u);
    assert.equal(seen.some(entry => entry.host === 'projref.supabase.co'), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 5 attack check calls the original data url with the public anon key only', async () => {
  const originalFetch = globalThis.fetch;
  const key = 'sb_publishable_abcdefghij1234567890';
  const original = 'https://projref.supabase.co/rest/v1/vault_notes';
  const step5 = { ...config, step: 5, originalApiUrl: original, identityProvider: { issuer: 'https://projref.supabase.co/auth/v1' } };
  const seen = [];
  const handler = (dataApiStatus, dataApiBody) => async (url, init = {}) => {
    const target = new URL(String(url));
    seen.push({ host: target.host, method: init.method ?? 'GET', search: target.search, apikey: init.headers?.apikey });
    if (target.host === 'projref.supabase.co') return Response.json(dataApiBody, { status: dataApiStatus });
    if (target.pathname === '/') return new Response(`<script>'${key}'</script>`, { status: 200 });
    if (target.pathname === '/data.json') return Response.json({ notes: [] });
    if ((init.method ?? 'GET') === 'PATCH') return new Response('no', { status: 405 });
    return Response.json({ error: '로그인이 필요합니다.' }, { status: 401 });
  };
  try {
    globalThis.fetch = handler(401, { code: '42501' });
    const results = await runAttackChecks(step5);
    const byId = Object.fromEntries(results.map(item => [item.attackId, item.observed]));
    assert.equal(byId.original_url_no_notes, '거부됨, 메모가 보이지 않음 (HTTP 401)');
    assert.equal(byId.anon_direct_read_rejected, '거부됨 (HTTP 401)');
    assert.match(byId.authenticated_direct_rejected, /^미실행/u);
    assert.match(byId.logged_in_own_crud, /^미실행/u);
    assert.match(byId.cross_user_access, /^미실행/u);
    assert.ok(seen.filter(entry => entry.host === 'projref.supabase.co').every(entry => entry.apikey === key));
    assert.ok(results.length <= 20);
    assert.equal(new Set(results.map(item => item.attackId)).size, results.length);
    assert.doesNotMatch(JSON.stringify(results), new RegExp(key, 'u'));

    globalThis.fetch = handler(200, [{ id: 'x' }]);
    const open = Object.fromEntries((await runAttackChecks(step5)).map(item => [item.attackId, item.observed]));
    assert.match(open.original_url_no_notes, /^원본 주소에서 메모가 보임/u);

    globalThis.fetch = handler(401, {});
    const noUrl = Object.fromEntries((await runAttackChecks({ ...step5, originalApiUrl: `${original}?select=*` })).map(item => [item.attackId, item.observed]));
    assert.match(noUrl.original_url_no_notes, /^미실행/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
