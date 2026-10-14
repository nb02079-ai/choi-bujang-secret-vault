// 1~11단계의 정상·금지 요청을 다시 실행해 기대 결과, 실제 결과, 요청 ID, 확인 시각을 한 표로 남깁니다.
// 실제 결과는 이 파일이 요청을 보내 실제로 받은 값뿐입니다. 사람이 적은 결과 문구나 성공 문구를 쓰지 않습니다.
//
// 출처 열의 뜻 (실측한 대상이 다릅니다):
//   핸들러: 실제 서버 함수 코드를 프로세스 안에서 가짜 저장소(메모리)로 호출한 결과입니다. 배포된 시스템과 실제 Supabase를 실측한 것이 아닙니다.
//   판정기: 실제 decide()·detect() 코드를 호출한 결과입니다.
//   파일:   저장소의 배포 파일을 읽은 결과입니다.
//   배포:   배포 주소로 보낸 실제 HTTP 응답입니다. 토큰 없이 보낼 수 있는 요청만, --deployed로 주소를 줄 때만 실행합니다.
// 실행하지 않은 요청은 '미실행'으로 표에 남기고 실제 결과·요청 ID·확인 시각을 '-'로 둡니다. 통과로 바꾸지 않습니다.
// 41종 공격은 목록이 없어 모두 미실행이며 이 파일은 그 결과를 만들지 않습니다.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { decide as realDecide } from './decider.mjs';
import { detect as realDetect } from './detect.mjs';
import { DEVICE_COOKIE, createDeviceApi, createDeviceCheck } from './device-api.mjs';
import { contentSha256, createNotesApi as realCreateNotesApi } from './notes-api.mjs';
import { PolicyCopyError, loadSnapshot } from './policy-diff.mjs';

export const SOURCE_LABELS = Object.freeze({ handler: '핸들러', decider: '판정기', file: '파일', deployed: '배포', none: '-' });
export const RESULT_LABELS = Object.freeze({ match: '일치', mismatch: '불일치', not_run: '미실행' });
export const ATTACK_TOTAL = 41;
const KIND_LABELS = Object.freeze({ normal: '정상', forbidden: '금지' });
const SAMPLE_ID = '00000000-0000-4000-8000-000000000000';

// ---- 가짜 저장소와 서버 함수 호출 도구 ----
function memoryFetch(tables) {
  return async (url, init) => {
    const rows = tables[url.pathname.split('/').pop()];
    if (!rows) return new Response('{}', { status: 404 });
    const query = Object.fromEntries(url.searchParams);
    const filters = Object.entries(query).filter(([key, value]) => !['select', 'limit', 'order'].includes(key) && typeof value === 'string' && value.startsWith('eq.'));
    const match = (row) => filters.every(([key, value]) => String(row[key]) === value.slice(3));
    const pick = (row) => (query.select ? Object.fromEntries(query.select.split(',').map((key) => [key, row[key]])) : row);
    const body = init.body ? JSON.parse(init.body) : undefined;
    const limited = (list) => (query.limit ? list.slice(0, Number(query.limit)) : list);
    if (init.method === 'GET') return Response.json(limited(rows.filter(match)).map(pick));
    if (init.method === 'POST') {
      if (body.id !== undefined && rows.some((row) => row.id === body.id)) return new Response('{}', { status: 409 });
      const row = { id: randomUUID(), ...body };
      rows.push(row);
      return Response.json([pick(row)], { status: 201 });
    }
    const hits = rows.filter(match);
    if (init.method === 'PATCH') { hits.forEach((row) => Object.assign(row, body)); return Response.json(hits.map(pick)); }
    hits.forEach((row) => rows.splice(rows.indexOf(row), 1));
    return Response.json(hits.map(pick));
  };
}

function fakeResponse() {
  const res = { headers: {}, statusCode: 0, body: undefined };
  res.setHeader = (key, value) => { res.headers[key.toLowerCase()] = value; };
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (body) => { res.body = body; return res; };
  return res;
}

async function invoke(handler, { method, url = '/api/x', token, cookie, body, headers = {}, requestId }) {
  const res = fakeResponse();
  const sent = { 'x-request-id': requestId, ...headers };
  if (token) sent.authorization = `Bearer ${token}`;
  if (cookie) sent.cookie = `${DEVICE_COOKIE}=${cookie}`;
  await handler({ method, url, headers: sent, body }, res);
  return res;
}

function createWorld(now, createNotesApi) {
  const [userA, userB] = [randomUUID(), randomUUID()];
  const [noteA, noteB] = [randomUUID(), randomUUID()];
  const [cookieA, cookieB] = [randomBytes(32).toString('base64url'), randomBytes(32).toString('base64url')];
  const digest = (value) => createHash('sha256').update(value).digest('hex');
  const original = { title: '시험 계정 B의 메모', content: 'B가 침해 전에 쓴 가상 내용' };
  const hash = contentSha256(original.title, original.content);
  const tables = {
    vault_notes: [
      { id: noteA, owner_id: userA, title: 'A의 메모', content: 'A의 내용' },
      // 3차 침공으로 내용이 바뀐 B의 메모
      { id: noteB, owner_id: userB, title: '침해된 제목', content: '침해된 내용' },
    ],
    vault_notes_backup: [{ id: noteB, owner_id: userB, ...original, content_sha256: hash }],
    vault_restore_audit: [],
    vault_devices: [
      { id: randomUUID(), owner_id: userA, secret_sha256: digest(cookieA), status: 'approved', request_code: 'AAAA2222', expires_at: null },
      { id: randomUUID(), owner_id: userB, secret_sha256: digest(cookieB), status: 'approved', request_code: 'BBBB3333', expires_at: null },
    ],
  };
  const env = { SUPABASE_URL: 'https://recheck.invalid', SUPABASE_SECRET_KEY: 'recheck-local-only' };
  const fetchImpl = memoryFetch(tables);
  const tokens = { 'Bearer tokenA': { kind: 'student', userId: userA }, 'Bearer tokenB': { kind: 'student', userId: userB } };
  const verify = async (authorization) => tokens[authorization] ?? null;
  return {
    tables, ids: { noteA, noteB }, users: { userA, userB }, cookies: { cookieA, cookieB }, original, hash,
    notes: createNotesApi({ verify, env, fetchImpl, deviceCheck: createDeviceCheck({ env, fetchImpl, now }) }),
    devices: createDeviceApi({ verify, env, fetchImpl, now }),
    snapshot: () => JSON.stringify(tables),
  };
}

// ---- 요청 목록 ----
const http = (res, extra = '') => `HTTP ${res.statusCode}${extra}`;
const verdict = (result) => `${result.decision} · ${result.reasonCode}`;
const fileText = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');

function decideRequest(overrides = {}) {
  return {
    schema: 'aleph.decision.v1', requestId: randomUUID(), classId: 'class_recheck', projectId: 'project_recheck',
    subjectId: 'learner_recheck', deviceId: 'a'.repeat(16), service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id',
    queryLength: 0, querySha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', at: new Date().toISOString(), policyRevision: 1,
    deviceRegistered: true, stepUp: { verified: false, authAgeSeconds: null }, recentEvents: [],
    signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 }, ...overrides,
  };
}
const SUSPICIOUS = { signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 }, recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }] };
const reads = (count, network) => Array.from({ length: count }, (_, index) => ({
  at: new Date(Date.UTC(2026, 9, 1, 0, 0, 0) + index * 2000).toISOString(), method: 'GET', identity: { sub: 'learner_recheck' }, deviceId: 'b'.repeat(16),
  signals: { source: 'judge_fixture', network, region: 'local', hour: 14 },
}));

// 실행하지 않는 요청: 이유와 함께 미실행으로 표에 남깁니다.
const notRunRows = () => [
  [4, 'forbidden', '공개 접속값으로 Data API 직접 읽기·추가·수정·삭제 (4건)', '거부 (401·403)', '환경변수 SUPABASE_PUBLISHABLE_KEY가 필요해 실행하지 않음'],
  [4, 'normal', 'A·B 실제 계정으로 각자 자기 메모 읽기·추가·수정·삭제 (배포)', 'HTTP 200·201', 'A·B 실제 계정의 로그인 토큰이 필요해 실행하지 않음'],
  [4, 'forbidden', 'B가 A의 메모를 읽기·수정·삭제 (배포, cross_user_access)', 'HTTP 404·403', 'A·B 실제 계정의 로그인 토큰이 필요해 실행하지 않음'],
  [5, 'forbidden', '공개 접속값으로 원본 자료 주소 직접 요청', '거부 또는 메모 0건', '환경변수 SUPABASE_PUBLISHABLE_KEY가 필요해 실행하지 않음'],
  [5, 'forbidden', '로그인 토큰을 실어 원본 자료 주소 직접 요청', '거부', '로그인 토큰이 필요해 실행하지 않음'],
  [5, 'normal', '서버 로그인 함수로 실제 로그인·갱신·로그아웃', 'HTTP 200', '실제 Supabase Auth와 계정이 필요해 실행하지 않음'],
  [7, 'forbidden', '다시 로그인 확인 전 실제 자료 차단과 새 요청 허용', '차단 뒤 허용', '제공 엔진의 새 로그인 시각 검증 계약을 확인하지 못해 실행하지 않음'],
  [9, 'forbidden', 'propose_revocation 제안의 실제 회수 집행과 걸린 시간', '회수됨', '실제 회수와 시간은 심판이 확인해 실행하지 않음'],
  [10, 'normal', '실제 DB에서 메모 한 건 복원 (005 SQL 실행 포함)', 'HTTP 200', '실제 Supabase와 B 계정이 필요해 실행하지 않음'],
  [11, 'normal', '두 기기의 실제 브라우저 승인 흐름 (쿠키·설치·오프라인)', '승인됨', '실제 브라우저와 배포 환경이 필요해 실행하지 않음'],
];

function localDefinitions(world, deps) {
  const { ids, users, cookies, hash } = world;
  const A = 'tokenA';
  const B = 'tokenB';
  const own = { token: A, cookie: cookies.cookieA };
  const noteUrl = (id) => `/api/notes/${id}`;
  let created;
  let pending;
  const same = (before) => (world.snapshot() === before ? ' · 저장소 변화 없음' : ' · 저장소 변화 있음');
  const call = (handler, options, requestId) => invoke(handler, { ...options, requestId });
  const denied = (step, title, request, expected, run) => ({ step, kind: 'forbidden', title, request, expected, source: 'handler', run });
  const allowed = (step, title, request, expected, run) => ({ step, kind: 'normal', title, request, expected, source: 'handler', run });
  const decision = (step, kind, title, request, expected, make) => ({
    step, kind, title, request, expected, source: 'decider',
    run: async (id) => {
      const req = make(id);
      const result = await deps.decide(req);
      const echoed = result?.requestId === id;
      return { actual: `${verdict(result)}${echoed ? '' : ' · 요청 ID 불일치'}`, ok: true };
    },
  });
  const fromId = (overrides) => (id) => decideRequest({ requestId: id, ...overrides });
  const noticeRoute = (method, route, path) => fromId({ service: 'notices', method, route: `${method} ${route}`, path });

  return [
    // 1단계
    { step: 1, kind: 'normal', title: '시작 화면 파일', request: 'public/index.html 읽기', expected: '파일 있음 · 자료실 제목', source: 'file',
      run: async () => { const text = fileText('../public/index.html'); return { actual: `파일 있음 · ${/<title>[^<]*자료실[^<]*<\/title>/u.test(text) ? '자료실 제목' : '제목 없음'}`, ok: true, noId: true }; } },
    // 2단계
    allowed(2, '로그인한 A가 자기 메모 목록 읽기', 'GET /api/notes (A, 승인된 기기)', 'HTTP 200 · 메모 1건',
      async (id) => { const res = await call(world.notes.collection, { method: 'GET', url: '/api/notes', ...own }, id); return { actual: http(res, ` · 메모 ${Array.isArray(res.body) ? res.body.length : '?'}건`) }; }),
    { step: 2, kind: 'forbidden', title: '공개 자료에 메모가 없음', request: 'public/data.json 읽기', expected: '공개 메모 0건', source: 'file',
      run: async () => { const data = JSON.parse(fileText('../public/data.json')); return { actual: `공개 메모 ${Array.isArray(data.notes) ? data.notes.length : '?'}건`, noId: true }; } },
    denied(2, '로그인 없이 메모 목록 읽기', 'GET /api/notes (토큰 없음)', 'HTTP 401', async (id) => ({ actual: http(await call(world.notes.collection, { method: 'GET', url: '/api/notes' }, id)) })),
    // 3단계
    allowed(3, 'A가 메모 추가', 'POST /api/notes (A)', 'HTTP 201', async (id) => {
      const res = await call(world.notes.collection, { method: 'POST', url: '/api/notes', ...own, body: { title: '재확인 메모', body: '재확인 내용' } }, id);
      created = res.body?.id;
      return { actual: http(res) };
    }),
    allowed(3, 'A가 방금 만든 메모 한 건 읽기', 'GET /api/notes/:id (A)', 'HTTP 200', async (id) => ({ actual: http(await call(world.notes.item, { method: 'GET', url: noteUrl(created), ...own }, id)) })),
    allowed(3, 'A가 방금 만든 메모 수정', 'PUT /api/notes/:id (A)', 'HTTP 200', async (id) => ({ actual: http(await call(world.notes.item, { method: 'PUT', url: noteUrl(created), ...own, body: { title: '수정한 메모', body: '수정한 내용' } }, id)) })),
    allowed(3, 'A가 방금 만든 메모 삭제', 'DELETE /api/notes/:id (A)', 'HTTP 200 · 저장소에서 삭제됨', async (id) => {
      const res = await call(world.notes.item, { method: 'DELETE', url: noteUrl(created), ...own }, id);
      return { actual: http(res, world.tables.vault_notes.some((row) => row.id === created) ? ' · 저장소에 남아 있음' : ' · 저장소에서 삭제됨') };
    }),
    denied(3, '로그인 없이 메모 추가', 'POST /api/notes (토큰 없음)', 'HTTP 401', async (id) => ({ actual: http(await call(world.notes.collection, { method: 'POST', url: '/api/notes', body: { title: 'x', body: 'y' } }, id)) })),
    denied(3, '로그인 없이 메모 한 건 읽기', 'GET /api/notes/:id (토큰 없음)', 'HTTP 401', async (id) => ({ actual: http(await call(world.notes.item, { method: 'GET', url: noteUrl(ids.noteA) }, id)) })),
    denied(3, '로그인 없이 메모 수정', 'PUT /api/notes/:id (토큰 없음)', 'HTTP 401', async (id) => ({ actual: http(await call(world.notes.item, { method: 'PUT', url: noteUrl(ids.noteA), body: { title: 'x', body: 'y' } }, id)) })),
    denied(3, '로그인 없이 메모 삭제', 'DELETE /api/notes/:id (토큰 없음)', 'HTTP 401', async (id) => ({ actual: http(await call(world.notes.item, { method: 'DELETE', url: noteUrl(ids.noteA) }, id)) })),
    denied(3, '가짜 토큰으로 메모 목록 읽기', 'GET /api/notes (가짜 토큰)', 'HTTP 401', async (id) => ({ actual: http(await call(world.notes.collection, { method: 'GET', url: '/api/notes', token: 'aaa.bbb.ccc' }, id)) })),
    denied(3, '토큰 없이 userId·role·owner_id를 위조해 메모 추가', 'POST /api/notes (위조 값, 토큰 없음)', 'HTTP 401', async (id) => ({
      actual: http(await call(world.notes.collection, { method: 'POST', url: '/api/notes', headers: { 'x-user-id': 'admin', 'x-role': 'admin' }, body: { title: 'x', body: 'y', owner_id: users.userA, role: 'admin' } }, id)),
    })),
    denied(3, '허용하지 않는 방식(PATCH)', 'PATCH /api/notes (A)', 'HTTP 405', async (id) => ({ actual: http(await call(world.notes.collection, { method: 'PATCH', url: '/api/notes', ...own }, id)) })),
    // 4단계
    allowed(4, 'B가 자기 메모 목록 읽기', 'GET /api/notes (B, 승인된 기기)', 'HTTP 200 · 메모 1건', async (id) => {
      const res = await call(world.notes.collection, { method: 'GET', url: '/api/notes', token: B, cookie: cookies.cookieB }, id);
      return { actual: http(res, ` · 메모 ${Array.isArray(res.body) ? res.body.length : '?'}건`) };
    }),
    denied(4, 'B가 A의 메모를 읽기', 'GET /api/notes/:id (B → A의 메모)', 'HTTP 404 · 저장소 변화 없음', async (id) => {
      const before = world.snapshot();
      return { actual: http(await call(world.notes.item, { method: 'GET', url: noteUrl(ids.noteA), token: B, cookie: cookies.cookieB }, id), same(before)) };
    }),
    denied(4, 'B가 A의 메모를 수정', 'PUT /api/notes/:id (B → A의 메모)', 'HTTP 404 · 저장소 변화 없음', async (id) => {
      const before = world.snapshot();
      return { actual: http(await call(world.notes.item, { method: 'PUT', url: noteUrl(ids.noteA), token: B, cookie: cookies.cookieB, body: { title: '탈취', body: 'x' } }, id), same(before)) };
    }),
    denied(4, 'B가 A의 메모를 삭제', 'DELETE /api/notes/:id (B → A의 메모)', 'HTTP 404 · 저장소 변화 없음', async (id) => {
      const before = world.snapshot();
      return { actual: http(await call(world.notes.item, { method: 'DELETE', url: noteUrl(ids.noteA), token: B, cookie: cookies.cookieB }, id), same(before)) };
    }),
    denied(4, 'A가 메모 소유자를 B로 바꾸려는 수정', 'PUT /api/notes/:id (본문 owner_id 위조)', 'HTTP 403 · 저장소 변화 없음', async (id) => {
      const before = world.snapshot();
      return { actual: http(await call(world.notes.item, { method: 'PUT', url: noteUrl(ids.noteA), ...own, body: { title: 'x', body: 'y', owner_id: users.userB } }, id), same(before)) };
    }),
    // 5단계
    allowed(5, 'A가 서버 함수를 거쳐 자기 메모 한 건 읽기', 'GET /api/notes/:id (A, 서버 함수 경유)', 'HTTP 200 · 제목 일치', async (id) => {
      const res = await call(world.notes.item, { method: 'GET', url: noteUrl(ids.noteA), ...own }, id);
      return { actual: http(res, res.body?.title === 'A의 메모' ? ' · 제목 일치' : ' · 제목 다름') };
    }),
    { step: 5, kind: 'forbidden', title: '첫 화면 코드에 접속값 형태의 문자열이 없음', request: 'public/index.html 검사', expected: '접속값 형태 0건', source: 'file',
      run: async () => {
        // 키 모양 패턴은 실행할 때 조립해 저장소 파일에 키 형태 글자가 남지 않게 합니다.
        const shape = new RegExp([`sb_${['publi', 'shable'].join('')}_[A-Za-z0-9_-]{10,}`, 'eyJ[A-Za-z0-9_-]{12,}\\.eyJ[A-Za-z0-9_-]{12,}\\.[A-Za-z0-9_-]{8,}'].join('|'), 'gu');
        return { actual: `접속값 형태 ${(fileText('../public/index.html').match(shape) ?? []).length}건`, noId: true };
      } },
    // 6단계
    decision(6, 'normal', '등록된 기기의 가상 요청', 'decide: deviceRegistered=true', 'allow · approved', fromId({})),
    decision(6, 'forbidden', '미등록 기기의 가상 요청', 'decide: deviceRegistered=false', 'deny · device_not_registered', fromId({ deviceRegistered: false })),
    // 7단계
    decision(7, 'normal', '정상 접속 사건', 'decide: 평소 시각·네트워크', 'allow · approved', fromId({})),
    decision(7, 'forbidden', '복합 이상 접속(새벽·처음 보는 네트워크·많은 읽기)', 'decide: 복합 이상 사건', 'step_up · step_up_required', fromId(SUSPICIOUS)),
    decision(7, 'normal', '다시 확인한 복합 이상 접속', 'decide: 복합 이상 + stepUp 재확인', 'allow · approved', fromId({ ...SUSPICIOUS, stepUp: { verified: true, authAgeSeconds: 60 } })),
    // 8단계
    decision(8, 'normal', '자기 메모 한 건 읽기', 'decide: GET /notes/:id', 'allow · approved', fromId({})),
    decision(8, 'normal', '자기 메모 한 건 수정', 'decide: PUT /notes/:id', 'allow · approved', fromId({ method: 'PUT', route: 'PUT /notes/:id' })),
    decision(8, 'normal', '자기 메모 한 건 삭제', 'decide: DELETE /notes/:id', 'allow · approved', fromId({ method: 'DELETE', route: 'DELETE /notes/:id' })),
    decision(8, 'normal', '반 공지 읽기', 'decide: GET /notices', 'allow · approved', noticeRoute('GET', '/notices', '/notices')),
    decision(8, 'forbidden', '메모 전체 목록 열기', 'decide: GET /notes', 'deny · route_not_allowed', fromId({ route: 'GET /notes', path: '/notes' })),
    decision(8, 'forbidden', '반 공지 쓰기', 'decide: POST /notices', 'deny · zone_forbidden', noticeRoute('POST', '/notices', '/notices')),
    decision(8, 'forbidden', '반 공지 수정', 'decide: PUT /notices/:id', 'deny · zone_forbidden', noticeRoute('PUT', '/notices/:id', '/notices/demo')),
    decision(8, 'forbidden', '강사 자료 읽기', 'decide: GET /instructor/:id', 'deny · zone_forbidden', fromId({ service: 'instructor', route: 'GET /instructor/:id', path: '/instructor/demo' })),
    decision(8, 'forbidden', '알 수 없는 경로', 'decide: GET /admin', 'deny · route_not_allowed', fromId({ route: 'GET /admin', path: '/admin' })),
    decision(8, 'forbidden', '자료 ID와 같은 깊이의 기능 경로', 'decide: GET /notes/export', 'deny · route_not_allowed', fromId({ path: '/notes/export' })),
    // 9단계
    { step: 9, kind: 'normal', title: '정상 조회 30건', request: 'detect: 같은 기기 GET 30건', expected: 'observe', source: 'decider',
      run: async () => ({ actual: deps.detect(reads(30, 'usual')).action, noId: true }) },
    { step: 9, kind: 'normal', title: '경계 120건 (평소와 다른 네트워크여도)', request: 'detect: GET 120건 + 평소와 다른 네트워크', expected: 'observe', source: 'decider',
      run: async () => ({ actual: deps.detect(reads(120, 'unusual')).action, noId: true }) },
    { step: 9, kind: 'forbidden', title: '10분 안에 121건 + 평소와 다른 네트워크', request: 'detect: GET 121건 + 평소와 다른 네트워크', expected: 'propose_revocation · burst_read · 기기 1개', source: 'decider',
      run: async () => {
        const result = deps.detect(reads(121, 'unusual'));
        return { actual: `${result.action} · ${result.reasonCode ?? '-'} · 기기 ${result.device ? 1 : 0}개`, noId: true };
      } },
    // 10단계
    denied(10, 'A가 B의 메모를 복원', 'POST /api/notes/:id/restore (A → B의 메모)', 'HTTP 404 · 저장소 변화 없음', async (id) => {
      const before = world.snapshot();
      return { actual: http(await call(world.notes.restore, { method: 'POST', url: `${noteUrl(ids.noteB)}/restore`, ...own, body: { contentSha256: hash } }, id), same(before)) };
    }),
    denied(10, '사본과 다른 해시로 복원', 'POST /api/notes/:id/restore (B, 틀린 해시)', 'HTTP 409 · 저장소 변화 없음', async (id) => {
      const before = world.snapshot();
      return { actual: http(await call(world.notes.restore, { method: 'POST', url: `${noteUrl(ids.noteB)}/restore`, token: B, cookie: cookies.cookieB, body: { contentSha256: 'f'.repeat(64) } }, id), same(before)) };
    }),
    { step: 10, kind: 'forbidden', title: '기대 지문이 없는 정책 사본', request: 'policy:diff (기대 지문 없음)', expected: '중단 · expected_missing', source: 'handler',
      run: async () => {
        try { loadSnapshot('policy/none.json', undefined); return { actual: '중단되지 않음', noId: true }; } catch (error) {
          return { actual: error instanceof PolicyCopyError ? `중단 · ${error.code}` : '중단 · 알 수 없는 오류', noId: true };
        }
      } },
    allowed(10, 'B가 자기 메모를 사본으로 복원', 'POST /api/notes/:id/restore (B, 맞는 해시)', 'HTTP 200 · 내용 해시가 사본과 같음 · 다른 메모 그대로', async (id) => {
      const othersBefore = JSON.stringify(world.tables.vault_notes.filter((row) => row.id !== ids.noteB));
      const res = await call(world.notes.restore, { method: 'POST', url: `${noteUrl(ids.noteB)}/restore`, token: B, cookie: cookies.cookieB, body: { contentSha256: hash } }, id);
      const row = world.tables.vault_notes.find((item) => item.id === ids.noteB);
      const sameHash = row && contentSha256(row.title, row.content) === hash && row.owner_id === users.userB;
      const othersAfter = JSON.stringify(world.tables.vault_notes.filter((item) => item.id !== ids.noteB));
      return { actual: http(res, `${sameHash ? ' · 내용 해시가 사본과 같음' : ' · 내용 해시가 사본과 다름'}${othersBefore === othersAfter ? ' · 다른 메모 그대로' : ' · 다른 메모 바뀜'}`) };
    }),
    // 11단계
    denied(11, '기기 쿠키 없이 자료 읽기', 'GET /api/notes (A, 쿠키 없음)', 'HTTP 403', async (id) => ({ actual: http(await call(world.notes.collection, { method: 'GET', url: '/api/notes', token: A }, id)) })),
    { step: 11, kind: 'normal', title: '새 기기가 승인을 요청', request: 'POST /api/device/request (A, 새 기기)', expected: 'HTTP 201 · 승인 대기', source: 'handler',
      run: async (id) => {
        const res = await call(world.devices.request, { method: 'POST', url: '/api/device/request', token: A }, id);
        pending = { cookie: /=([A-Za-z0-9_-]{43});/u.exec(res.headers['set-cookie'] ?? '')?.[1], code: res.body?.code };
        return { actual: http(res, ` · ${res.body?.status === 'pending' ? '승인 대기' : '승인 대기 아님'}`) };
      } },
    denied(11, '승인 대기 중인 기기로 자료 읽기', 'GET /api/notes (A, 대기 기기)', 'HTTP 403', async (id) => ({ actual: http(await call(world.notes.collection, { method: 'GET', url: '/api/notes', token: A, cookie: pending?.cookie }, id)) })),
    denied(11, '대기 중인 기기가 자기 코드로 승인', 'POST /api/device/approve (A, 대기 기기)', 'HTTP 403 · 상태 그대로 승인 대기', async (id) => {
      const res = await call(world.devices.approve, { method: 'POST', url: '/api/device/approve', token: A, cookie: pending?.cookie, body: { code: pending?.code } }, id);
      const row = world.tables.vault_devices.find((item) => item.request_code === pending?.code);
      return { actual: http(res, row?.status === 'pending' ? ' · 상태 그대로 승인 대기' : ' · 상태가 바뀜') };
    }),
    allowed(11, '승인된 기기에서 새 기기의 코드를 승인', 'POST /api/device/approve (A, 승인된 기기)', 'HTTP 200', async (id) => ({
      actual: http(await call(world.devices.approve, { method: 'POST', url: '/api/device/approve', ...own, body: { code: pending?.code } }, id)),
    })),
    allowed(11, '승인된 새 기기로 자료 읽기', 'GET /api/notes (A, 승인된 새 기기)', 'HTTP 200', async (id) => ({ actual: http(await call(world.notes.collection, { method: 'GET', url: '/api/notes', token: A, cookie: pending?.cookie }, id)) })),
  ];
}

// ---- 배포 주소로 보내는 요청(토큰 없이 가능한 것만) ----
function deployedDefinitions() {
  const probe = (step, kind, title, request, expected, path, init, summarize) => ({ step, kind, title, request, expected, source: 'deployed', path, init, summarize });
  const code = (response) => `HTTP ${response.status}`;
  return [
    probe(1, 'normal', '배포된 화면 열기', 'GET / (배포)', 'HTTP 200 · 자료실 제목', '/', { method: 'GET' }, (r) => `HTTP ${r.status} · ${/<title>[^<]*자료실/u.test(r.text) ? '자료실 제목' : '제목 없음'}`),
    probe(2, 'forbidden', '배포된 공개 자료에 메모가 없음', 'GET /data.json (배포)', 'HTTP 200 · 공개 메모 0건', '/data.json', { method: 'GET' }, (r) => {
      let count = '?';
      try { const data = JSON.parse(r.text); count = Array.isArray(data.notes) ? data.notes.length : '?'; } catch { /* 형식 오류 */ }
      return `HTTP ${r.status} · 공개 메모 ${count}건`;
    }),
    probe(3, 'forbidden', '로그인 없이 메모 목록 읽기 (배포)', 'GET /api/notes (배포, 토큰 없음)', 'HTTP 401', '/api/notes', { method: 'GET' }, code),
    probe(3, 'forbidden', '로그인 없이 메모 추가 (배포)', 'POST /api/notes (배포, 토큰 없음)', 'HTTP 401', '/api/notes', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"title":"x","body":"y"}' }, code),
    probe(3, 'forbidden', '로그인 없이 메모 한 건 읽기 (배포)', 'GET /api/notes/:id (배포, 토큰 없음)', 'HTTP 401', `/api/notes/${SAMPLE_ID}`, { method: 'GET' }, code),
    probe(3, 'forbidden', '로그인 없이 메모 삭제 (배포)', 'DELETE /api/notes/:id (배포, 토큰 없음)', 'HTTP 401', `/api/notes/${SAMPLE_ID}`, { method: 'DELETE' }, code),
    probe(3, 'forbidden', '가짜 토큰으로 메모 목록 읽기 (배포)', 'GET /api/notes (배포, 가짜 토큰)', 'HTTP 401', '/api/notes', { method: 'GET', headers: { Authorization: 'Bearer aaa.bbb.ccc' } }, code),
    probe(3, 'forbidden', '허용하지 않는 방식 (배포)', 'PATCH /api/notes (배포)', 'HTTP 405', '/api/notes', { method: 'PATCH' }, code),
    probe(5, 'forbidden', '배포된 첫 화면에 접속값 형태가 없음', 'GET / (배포)', '접속값 형태 0건', '/', { method: 'GET' }, (r) => {
      const shape = new RegExp([`sb_${['publi', 'shable'].join('')}_[A-Za-z0-9_-]{10,}`, 'eyJ[A-Za-z0-9_-]{12,}\\.eyJ[A-Za-z0-9_-]{12,}\\.[A-Za-z0-9_-]{8,}'].join('|'), 'gu');
      return `접속값 형태 ${(r.text.match(shape) ?? []).length}건`;
    }),
    probe(11, 'forbidden', '로그인 없이 기기 상태 조회 (배포)', 'GET /api/device/status (배포, 토큰 없음)', 'HTTP 401', '/api/device/status', { method: 'GET' }, code),
    probe(11, 'forbidden', '로그인 없이 기기 승인 요청 (배포)', 'POST /api/device/request (배포, 토큰 없음)', 'HTTP 401', '/api/device/request', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }, code),
    probe(11, 'forbidden', '로그인 없이 기기 승인 (배포)', 'POST /api/device/approve (배포, 토큰 없음)', 'HTTP 401', '/api/device/approve', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"code":"ABCDEFGH"}' }, code),
  ];
}

// ---- 실행 ----
const toRow = (definition, partial) => ({
  step: definition.step, kind: definition.kind, title: definition.title, request: definition.request, expected: definition.expected,
  source: 'none', actual: null, result: 'not_run', requestId: null, checkedAt: null, note: '', ...partial,
});

export async function runRecheck({ now = () => new Date(), fetchImpl = fetch, baseUrl = null, deps = {} } = {}) {
  const wiring = { decide: deps.decide ?? realDecide, detect: deps.detect ?? realDetect };
  const rows = [];
  const quietWarn = console.warn;
  const quietError = console.error;
  console.warn = () => {};
  console.error = () => {};
  try {
    const world = createWorld(() => now().getTime(), deps.createNotesApi ?? realCreateNotesApi);
    for (const definition of localDefinitions(world, wiring)) {
      const requestId = randomUUID();
      let outcome;
      try { outcome = await definition.run(requestId); } catch (error) { outcome = { actual: `오류 · ${error?.name ?? 'Error'}`, failed: true }; }
      const checkedAt = now().toISOString();
      const matched = !outcome.failed && outcome.actual === definition.expected;
      rows.push(toRow(definition, {
        source: definition.source, actual: outcome.actual, result: matched ? 'match' : 'mismatch',
        requestId: outcome.noId ? '-(파일·함수 호출)' : requestId, checkedAt,
      }));
    }
  } finally {
    console.warn = quietWarn;
    console.error = quietError;
  }

  for (const definition of deployedDefinitions()) {
    if (!baseUrl) {
      rows.push(toRow(definition, { note: '--deployed <배포 주소>를 주지 않아 실행하지 않음' }));
      continue;
    }
    const requestId = randomUUID();
    let outcome;
    let platformId = '';
    try {
      const response = await fetchImpl(new URL(definition.path, baseUrl), {
        ...definition.init, redirect: 'error', signal: AbortSignal.timeout(10000),
        headers: { ...(definition.init.headers ?? {}), 'x-request-id': requestId },
      });
      platformId = response.headers?.get?.('x-vercel-id') ?? '';
      const text = await response.text();
      outcome = { actual: definition.summarize({ status: response.status, text }) };
    } catch {
      outcome = { actual: '요청 실패 · 응답 없음', failed: true };
    }
    rows.push(toRow(definition, {
      source: 'deployed', actual: outcome.actual, result: !outcome.failed && outcome.actual === definition.expected ? 'match' : 'mismatch',
      requestId: platformId ? `${requestId} (vercel: ${platformId})` : requestId, checkedAt: now().toISOString(),
    }));
  }

  for (const [step, kind, title, expected, note] of notRunRows()) {
    rows.push(toRow({ step, kind, title, request: title, expected }, { note }));
  }
  rows.sort((a, b) => a.step - b.step);
  return { generatedAt: now().toISOString(), baseUrl, rows, summary: summarize(rows) };
}

export function summarize(rows) {
  const count = (predicate) => rows.filter(predicate).length;
  const steps = {};
  for (const row of rows) {
    const entry = (steps[row.step] ??= { normalMeasured: 0, forbiddenMeasured: 0, notRun: 0, mismatch: 0 });
    if (row.result === 'not_run') entry.notRun += 1;
    else {
      if (row.kind === 'normal') entry.normalMeasured += 1; else entry.forbiddenMeasured += 1;
      if (row.result === 'mismatch') entry.mismatch += 1;
    }
  }
  return {
    total: rows.length, match: count((row) => row.result === 'match'), mismatch: count((row) => row.result === 'mismatch'), notRun: count((row) => row.result === 'not_run'),
    measured: count((row) => row.result !== 'not_run'), steps,
    // 41종 공격은 목록과 심판 판정이 없어 여기서 만든 결과가 없습니다.
    attacks: { declared: ATTACK_TOTAL, listed: 0, measured: 0, notRun: ATTACK_TOTAL },
  };
}

const cell = (value) => String(value ?? '-').replaceAll('|', '\\|').replaceAll('\n', ' ');

export function renderReport({ generatedAt, baseUrl, rows, summary }) {
  const lines = [
    '# 1~11단계 정상·금지 요청 재확인 표',
    '',
    `확인 시각 기준: ${generatedAt} · 배포 주소 요청: ${baseUrl ? '실행' : '실행하지 않음(--deployed 없음)'}`,
    '',
    '출처 안내: **핸들러**와 **판정기**는 실제 코드를 프로세스 안에서 호출한 실측이며 배포된 시스템과 실제 Supabase를 실측한 것이 아닙니다. **배포**는 배포 주소로 보낸 실제 HTTP 응답입니다. **미실행**은 실행하지 않은 요청이며 통과로 세지 않습니다.',
    '',
    '| 단계 | 구분 | 요청 | 기대 | 실제 | 결과 | 요청 ID | 확인 시각 | 출처 |',
    '|---|---|---|---|---|---|---|---|---|',
    ...rows.map((row) => `| ${row.step} | ${KIND_LABELS[row.kind]} | ${cell(row.title)}${row.request === row.title ? '' : `<br>\`${cell(row.request)}\``} | ${cell(row.expected)} | ${cell(row.result === 'not_run' ? `- (${row.note})` : row.actual)} | ${RESULT_LABELS[row.result]} | ${cell(row.requestId)} | ${cell(row.checkedAt)} | ${SOURCE_LABELS[row.source]} |`),
    '',
    `요약: 전체 ${summary.total}건 · 실측 ${summary.measured}건(일치 ${summary.match}, 불일치 ${summary.mismatch}) · 미실행 ${summary.notRun}건`,
    `41종 공격 방어: 선언 ${summary.attacks.declared}종 · 목록 ${summary.attacks.listed}건 · 실측 ${summary.attacks.measured}건 · 미실행 ${summary.attacks.notRun}종 (목록과 심판 판정이 없어 통과로 처리하지 않음)`,
    '',
  ];
  return lines.join('\n');
}
