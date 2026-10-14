import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { contentSha256, createNotesApi } from '../src/notes-api.mjs';

const USER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOTE_A = '11111111-1111-4111-8111-111111111111';
const NOTE_B = '22222222-2222-4222-8222-222222222222';
const NOTE_B2 = '33333333-3333-4333-8333-333333333333';
const NOTE_NEW = '44444444-4444-4444-8444-444444444444';
// 키 모양 가짜 값은 실행할 때 조립해 저장소 파일에 키 형태 문자열이 남지 않게 합니다.
const STORE_VALUE = [['sb', ['sec', 'ret'].join(''), ''].join('_'), 'restore_value'].join('');
const clone = value => JSON.parse(JSON.stringify(value));

// 시험 계정 B의 메모 원본(침해 전)과 사본
const ORIGINAL = { title: 'B의 시험 메모', content: 'B가 침해 전에 쓴 가상 내용' };
const makeBackup = (id, owner, fields = ORIGINAL) => ({ id, owner_id: owner, ...fields, content_sha256: contentSha256(fields.title, fields.content) });
const HASH = contentSha256(ORIGINAL.title, ORIGINAL.content);

function fakeResponse() {
  const res = { headers: {}, statusCode: 0, body: undefined };
  res.setHeader = (key, value) => { res.headers[key.toLowerCase()] = value; };
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (body) => { res.body = body; return res; };
  return res;
}

// 표 세 개를 흉내 내는 메모리 저장소입니다. dropWrites는 쓰기가 반영되지 않는 상황, failAudit은 감사 기록 실패를 흉내 냅니다.
function memoryStore({ notes, backups, audits = [], dropWrites = false, failAudit = false } = {}) {
  const tables = { vault_notes: notes, vault_notes_backup: backups, vault_restore_audit: audits };
  const calls = [];
  const fetchImpl = async (url, init) => {
    const name = url.pathname.split('/').pop();
    const rows = tables[name];
    const query = Object.fromEntries(url.searchParams);
    const eq = field => (query[field]?.startsWith('eq.') ? query[field].slice(3) : undefined);
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method: init.method, name, body });
    const pick = row => (query.select ? Object.fromEntries(query.select.split(',').map(key => [key, row[key]])) : row);
    const matching = () => rows.filter(row => (eq('id') === undefined || row.id === eq('id'))
      && (eq('owner_id') === undefined || row.owner_id === eq('owner_id')));
    if (init.method === 'GET') return Response.json(matching().map(pick));
    if (init.method === 'POST') {
      if (name === 'vault_restore_audit' && failAudit) return new Response('{}', { status: 500 });
      if (rows.some(row => body.id !== undefined && row.id === body.id)) return new Response('{}', { status: 409 });
      if (!dropWrites || name === 'vault_restore_audit') rows.push({ ...body });
      return name === 'vault_restore_audit' ? new Response(null, { status: 201 }) : Response.json([pick({ ...body })], { status: 201 });
    }
    if (init.method === 'PATCH') {
      const hit = matching();
      if (!dropWrites) hit.forEach(row => Object.assign(row, body));
      return Response.json(hit.map(pick));
    }
    const hit = matching();
    hit.forEach(row => rows.splice(rows.indexOf(row), 1));
    return Response.json(hit.map(pick));
  };
  return { tables, calls, fetchImpl };
}

function fixture(options = {}) {
  const store = memoryStore({
    notes: options.notes ?? [
      // 3차 침공으로 B의 메모 내용이 바뀐 상태
      { id: NOTE_B, owner_id: USER_B, title: '침해된 제목', content: '침해된 내용' },
      { id: NOTE_B2, owner_id: USER_B, title: 'B의 다른 메모', content: '건드리면 안 되는 내용' },
      { id: NOTE_A, owner_id: USER_A, title: 'A의 메모', content: 'A의 내용' },
    ],
    backups: options.backups ?? [makeBackup(NOTE_B, USER_B), makeBackup(NOTE_A, USER_A, { title: 'A의 메모', content: 'A의 내용' })],
    audits: options.audits ?? [{ id: 1, note_id: NOTE_A, owner_id: USER_A, content_sha256: 'e'.repeat(64), outcome: 'restored' },
      { id: 2, note_id: NOTE_B2, owner_id: USER_B, content_sha256: 'f'.repeat(64), outcome: 'restored' }],
    dropWrites: options.dropWrites, failAudit: options.failAudit,
  });
  const tokens = {
    'Bearer tokenA.aaa.aaa': { kind: 'student', userId: USER_A },
    'Bearer tokenB.bbb.bbb': { kind: 'student', userId: USER_B },
    'Bearer judgeB.bbb.bbb': { kind: 'judge', userId: USER_B, runId: 'run', identity: 'b' },
  };
  const api = createNotesApi({ verify: async authorization => tokens[authorization] ?? null, fetchImpl: store.fetchImpl,
    env: { SUPABASE_URL: 'https://example-project.supabase.co', SUPABASE_SECRET_KEY: STORE_VALUE } });
  const warn = mock.method(console, 'warn', () => {});
  const error = mock.method(console, 'error', () => {});
  const logs = () => [...warn.mock.calls, ...error.mock.calls].map(entry => entry.arguments.join(' ')).join('\n');
  const call = async (method, { token, id = NOTE_B, body = { contentSha256: HASH }, url, headers = {}, query } = {}) => {
    const res = fakeResponse();
    const authorization = token ? { authorization: `Bearer ${token}` } : {};
    await api.restore({ method, url: url ?? `/api/notes/${id}/restore`, query, headers: { ...authorization, ...headers }, body }, res);
    return res;
  };
  return { store, call, logs, A: 'tokenA.aaa.aaa', B: 'tokenB.bbb.bbb', J: 'judgeB.bbb.bbb', done: () => { warn.mock.restore(); error.mock.restore(); } };
}
const snapshotOf = f => JSON.stringify(f.store.tables);
const row = (f, id) => f.store.tables.vault_notes.find(item => item.id === id);

test('내용 해시: 제목, 0x00, 내용 순서의 SHA-256이고 구분이 모호하지 않다', () => {
  assert.equal(contentSha256('a', 'b'), createHash('sha256').update('a\u0000b').digest('hex'));
  assert.equal(contentSha256('제목', '내용 🙂'), createHash('sha256').update('제목\u0000내용 🙂').digest('hex'));
  assert.notEqual(contentSha256('ab', ''), contentSha256('a', 'b'));
  assert.notEqual(contentSha256('a', 'b'), contentSha256('', 'ab'));
  assert.match(HASH, /^[0-9a-f]{64}$/u);
});

test('시험 계정 B의 침해된 메모 한 건이 사본으로 복원되고 ID·소유자·내용 해시가 사본과 같다', async () => {
  const f = fixture();
  try {
    const others = JSON.stringify([row(f, NOTE_B2), row(f, NOTE_A)]);
    const priorAudits = JSON.stringify(f.store.tables.vault_restore_audit);
    const backups = JSON.stringify(f.store.tables.vault_notes_backup);
    const res = await f.call('POST', { token: f.B });
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body, { id: NOTE_B, restored: true, contentSha256: HASH });
    const restored = row(f, NOTE_B);
    const backup = f.store.tables.vault_notes_backup.find(item => item.id === NOTE_B);
    assert.equal(restored.id, backup.id);
    assert.equal(restored.owner_id, backup.owner_id);
    assert.equal(contentSha256(restored.title, restored.content), backup.content_sha256);
    assert.deepEqual({ title: restored.title, content: restored.content }, ORIGINAL);
    // 다른 메모, 사본, 기존 감사 기록은 그대로이고 감사 기록은 한 줄만 늘어난다
    assert.equal(JSON.stringify([row(f, NOTE_B2), row(f, NOTE_A)]), others);
    assert.equal(JSON.stringify(f.store.tables.vault_notes_backup), backups);
    const audits = f.store.tables.vault_restore_audit;
    assert.equal(JSON.stringify(audits.slice(0, 2)), priorAudits);
    assert.equal(audits.length, 3);
    assert.deepEqual(audits[2], { note_id: NOTE_B, owner_id: USER_B, content_sha256: HASH, outcome: 'restored' });
    assert.ok(!JSON.stringify(res.body).includes(ORIGINAL.content));
    // 쓰기 호출은 B의 메모 한 건과 감사 한 줄뿐
    const writes = f.store.calls.filter(call => call.method !== 'GET').map(call => `${call.method} ${call.name}`);
    assert.deepEqual(writes, ['PATCH vault_notes', 'POST vault_restore_audit']);
  } finally { f.done(); }
});

test('지워진 B의 메모도 사본의 ID·소유자로 한 건만 되살린다', async () => {
  const f = fixture({ notes: [{ id: NOTE_A, owner_id: USER_A, title: 'A의 메모', content: 'A의 내용' }] });
  try {
    const res = await f.call('POST', { token: f.B });
    assert.equal(res.statusCode, 200);
    assert.equal(f.store.tables.vault_notes.length, 2);
    const restored = row(f, NOTE_B);
    assert.equal(restored.owner_id, USER_B);
    assert.equal(contentSha256(restored.title, restored.content), HASH);
    assert.deepEqual(row(f, NOTE_A), { id: NOTE_A, owner_id: USER_A, title: 'A의 메모', content: 'A의 내용' });
    const judge = fixture({ notes: [] });
    try { assert.equal((await judge.call('POST', { token: judge.J })).statusCode, 200); } finally { judge.done(); }
  } finally { f.done(); }
});

test('요청 해시가 사본과 다르거나 형식이 틀리면 복원하지 않는다', async () => {
  const f = fixture();
  try {
    const before = snapshotOf(f);
    assert.equal((await f.call('POST', { token: f.B, body: { contentSha256: 'a'.repeat(64) } })).statusCode, 409);
    assert.equal((await f.call('POST', { token: f.B, body: { contentSha256: contentSha256('침해된 제목', '침해된 내용') } })).statusCode, 409);
    for (const body of [{}, { contentSha256: 'abc' }, { contentSha256: HASH.toUpperCase() }, { contentSha256: 7 }, { contentSha256: [HASH] }, null, 'x', []]) {
      assert.equal((await f.call('POST', { token: f.B, body })).statusCode, 400, JSON.stringify(body));
    }
    assert.equal(snapshotOf(f), before);
  } finally { f.done(); }
});

test('사본 내용이 바뀌어 저장된 해시와 다르면 복원하지 않는다', async () => {
  const backup = makeBackup(NOTE_B, USER_B);
  backup.content = '사본이 몰래 바뀐 내용';
  const f = fixture({ backups: [backup] });
  try {
    const before = snapshotOf(f);
    const res = await f.call('POST', { token: f.B });
    assert.equal(res.statusCode, 409);
    assert.equal(snapshotOf(f), before);
  } finally { f.done(); }
});

test('남의 사본·남의 메모·사본 없음은 모두 같은 404이고 저장소는 그대로다', async () => {
  const foreignBackup = makeBackup(NOTE_B, USER_A); // 사본의 소유자가 A로 바뀐 상태
  const cases = [
    ['A가 B의 메모를 복원 요청', fixture(), 'A', NOTE_B],
    ['B가 A의 메모를 복원 요청', fixture(), 'B', NOTE_A],
    ['사본이 없음', fixture({ backups: [] }), 'B', NOTE_B],
    ['사본의 소유자가 다름', fixture({ backups: [foreignBackup] }), 'B', NOTE_B],
    ['사본의 소유자가 비어 있음', fixture({ backups: [{ ...makeBackup(NOTE_B, USER_B), owner_id: null }] }), 'B', NOTE_B],
    ['현재 행이 남의 소유', fixture({ notes: [{ id: NOTE_B, owner_id: USER_A, title: 'x', content: 'y' }] }), 'B', NOTE_B],
    ['현재 행의 소유자가 없음', fixture({ notes: [{ id: NOTE_B, owner_id: null, title: 'x', content: 'y' }] }), 'B', NOTE_B],
    ['ID 형식 오류', fixture(), 'B', 'not-a-uuid'],
  ];
  const bodies = new Set();
  try {
    for (const [label, f, who, id] of cases) {
      const before = snapshotOf(f);
      const res = await f.call('POST', { token: f[who], id, body: { contentSha256: HASH } });
      assert.equal(res.statusCode, 404, label);
      bodies.add(JSON.stringify(res.body));
      assert.equal(snapshotOf(f), before, label);
      f.done();
    }
    assert.equal(bodies.size, 1, '존재 여부를 구분하지 못하게 응답이 모두 같음');
  } finally { for (const [, f] of cases) f.done(); }
});

test('로그인이 없거나 방식이 틀리면 거부한다', async () => {
  const f = fixture();
  try {
    const before = snapshotOf(f);
    assert.equal((await f.call('POST', {})).statusCode, 401);
    assert.equal((await f.call('POST', { token: 'forged.aaa.bbb' })).statusCode, 401);
    for (const method of ['GET', 'PUT', 'DELETE', 'PATCH', 'HEAD']) {
      const res = await f.call(method, { token: f.B });
      assert.equal(res.statusCode, 405, method);
      assert.equal(res.headers.allow, 'POST');
    }
    assert.equal(snapshotOf(f), before);
  } finally { f.done(); }
});

test('요청의 role·owner_id·헤더는 권한이 되지 않고 이유 코드만 기록한다', async () => {
  const f = fixture();
  try {
    const before = snapshotOf(f);
    const forged = await f.call('POST', { token: f.A, id: NOTE_B, body: { contentSha256: HASH, role: 'instructor', owner_id: USER_B, userId: USER_B },
      headers: { 'x-user-id': USER_B, 'x-role': 'admin' }, query: { owner_id: USER_B } });
    assert.equal(forged.statusCode, 404);
    assert.equal(snapshotOf(f), before);
    const own = await f.call('POST', { token: f.B, body: { contentSha256: HASH, role: 'instructor', owner_id: USER_A } });
    assert.equal(own.statusCode, 200);
    assert.equal(row(f, NOTE_B).owner_id, USER_B, '본문의 owner_id로 소유자가 바뀌지 않음');
    assert.match(f.logs(), /privilege_field_ignored/u);
  } finally { f.done(); }
});

test('쓴 뒤 확인에 실패하거나 감사 기록을 못 쓰면 이전 상태로 되돌린다', async () => {
  const dropped = fixture({ dropWrites: true });
  try {
    const before = snapshotOf(dropped);
    const res = await dropped.call('POST', { token: dropped.B });
    assert.equal(res.statusCode, 500);
    assert.equal(snapshotOf(dropped), before);
  } finally { dropped.done(); }
  const noAudit = fixture({ failAudit: true });
  try {
    const before = snapshotOf(noAudit);
    const res = await noAudit.call('POST', { token: noAudit.B });
    assert.equal(res.statusCode, 500);
    assert.equal(snapshotOf(noAudit), before, '감사 기록이 없으면 복원도 남기지 않음');
  } finally { noAudit.done(); }
  const created = fixture({ notes: [], failAudit: true });
  try {
    const res = await created.call('POST', { token: created.B });
    assert.equal(res.statusCode, 500);
    assert.equal(created.store.tables.vault_notes.length, 0, '새로 넣은 행도 되돌림');
  } finally { created.done(); }
});

test('저장소 오류와 연결 실패에도 응답을 돌려주고 내용·해시·토큰·ID는 로그에 없다', async () => {
  const f = fixture();
  try {
    await f.call('POST', { token: f.B });
    await f.call('POST', { token: f.A });
    await f.call('POST', { token: f.B, body: { contentSha256: 'b'.repeat(64) } });
    const broken = createNotesApi({ verify: async () => ({ kind: 'student', userId: USER_B }),
      fetchImpl: async () => { throw new Error(`연결 실패 ${STORE_VALUE}`); },
      env: { SUPABASE_URL: 'https://example-project.supabase.co', SUPABASE_SECRET_KEY: STORE_VALUE } });
    const res = fakeResponse();
    await broken.restore({ method: 'POST', url: `/api/notes/${NOTE_B}/restore`, headers: { authorization: 'Bearer x.y.z' }, body: { contentSha256: HASH } }, res);
    assert.equal(res.statusCode, 500);
    const text = `${f.logs()}\n${JSON.stringify(res.body)}`;
    for (const secret of [STORE_VALUE, HASH, ORIGINAL.content, ORIGINAL.title, NOTE_B, USER_B, 'tokenB', 'tokenA']) {
      assert.ok(!text.includes(secret), secret);
    }
  } finally { f.done(); }
});

test('경로에서 ID를 읽는다: restore 구간 앞의 UUID만 쓰고 ID 자리의 restore는 거부한다', async () => {
  const f = fixture();
  try {
    const before = snapshotOf(f);
    for (const url of ['/api/notes/restore', `/api/notes/${NOTE_B}`, `/api/notes/${NOTE_B}/restore/extra`, '/api/notes//restore']) {
      assert.equal((await f.call('POST', { token: f.B, url })).statusCode, 404, url);
    }
    assert.equal(snapshotOf(f), before);
    const viaQuery = await f.call('POST', { token: f.B, url: '/api/notes/[id]/restore', query: { id: NOTE_B.toUpperCase() } });
    assert.equal(viaQuery.statusCode, 200);
  } finally { f.done(); }
});
