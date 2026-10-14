import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { RULE_IDS, describePolicy } from '../src/decider.mjs';
import { DETECTION_RULE } from '../src/detect.mjs';
import { DEVICE_COOKIE, createDeviceCheck } from '../src/device-api.mjs';
import { FETCH_LIMIT, OPS_SCHEMA, RECORD_LIMIT, createOpsApi, opsApi } from '../src/ops-api.mjs';
import { canonical } from '../src/policy-diff.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const config = JSON.parse(readFileSync(`${root}aleph.config.json`, 'utf8'));
const USER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
// 키 모양 가짜 값은 실행할 때 조립해 저장소 파일에 키 형태 문자열이 남지 않게 합니다.
const STORE_VALUE = [['sb', ['sec', 'ret'].join(''), ''].join('_'), 'ops_value'].join('');
const sha = (value) => createHash('sha256').update(value).digest('hex');
const NOW = Date.parse('2026-10-14T00:00:00Z');
const COOKIE_APPROVED = 'a'.repeat(43);
const COOKIE_PENDING = 'b'.repeat(43);
const hex = (char) => char.repeat(64);
const stamp = (offsetMinutes) => new Date(NOW + offsetMinutes * 60000).toISOString();

function fakeResponse() {
  const res = { headers: {}, statusCode: 0, body: undefined };
  res.setHeader = (key, value) => { res.headers[key.toLowerCase()] = value; };
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (body) => { res.body = body; return res; };
  return res;
}

function seed() {
  const device = (id, owner, status, extra = {}) => ({ id, owner_id: owner, secret_sha256: sha(id), status, request_code: 'ABCD2345',
    created_at: stamp(-60), decided_at: status === 'pending' ? null : stamp(-30), expires_at: stamp(15), decided_by: 'operator', ...extra });
  return {
    vault_devices: [
      device('a1a1a1a1-0000-4000-8000-000000000001', USER_A, 'approved', { secret_sha256: sha(COOKIE_APPROVED), created_at: stamp(-600) }),
      device('a2a2a2a2-0000-4000-8000-000000000002', USER_A, 'pending', { secret_sha256: sha(COOKIE_PENDING), created_at: stamp(-5) }),
      device('a3a3a3a3-0000-4000-8000-000000000003', USER_A, 'pending', { expires_at: stamp(-10), created_at: stamp(-120) }),
      device('a4a4a4a4-0000-4000-8000-000000000004', USER_A, 'revoked', { created_at: stamp(-300) }),
      device('a5a5a5a5-0000-4000-8000-000000000005', USER_A, 'denied', { created_at: stamp(-200) }),
      device('b1b1b1b1-0000-4000-8000-000000000006', USER_B, 'approved', { created_at: stamp(-100) }),
    ],
    vault_notes_backup: [
      { id: 'c1c1c1c1-0000-4000-8000-000000000011', owner_id: USER_A, title: 'SECRET-TITLE-1', content: 'SECRET-BODY-1', content_sha256: hex('1'), backed_up_at: stamp(-500) },
      { id: 'c2c2c2c2-0000-4000-8000-000000000012', owner_id: USER_A, title: 'SECRET-TITLE-2', content: 'SECRET-BODY-2', content_sha256: hex('2'), backed_up_at: stamp(-400) },
      { id: 'd1d1d1d1-0000-4000-8000-000000000013', owner_id: USER_B, title: 'SECRET-B', content: 'SECRET-B-BODY', content_sha256: hex('3'), backed_up_at: stamp(-300) },
    ],
    vault_restore_audit: [
      { id: 1, note_id: 'c1c1c1c1-0000-4000-8000-000000000011', owner_id: USER_A, content_sha256: hex('1'), outcome: 'restored', restored_at: stamp(-50) },
      { id: 2, note_id: 'c2c2c2c2-0000-4000-8000-000000000012', owner_id: USER_A, content_sha256: hex('2'), outcome: 'restored', restored_at: stamp(-40) },
      { id: 3, note_id: 'c1c1c1c1-0000-4000-8000-000000000011', owner_id: USER_A, content_sha256: hex('4'), outcome: 'restored', restored_at: stamp(-10) },
      { id: 4, note_id: 'd1d1d1d1-0000-4000-8000-000000000013', owner_id: USER_B, content_sha256: hex('3'), outcome: 'restored', restored_at: stamp(-20) },
    ],
    vault_notes: [{ id: 'e1e1e1e1-0000-4000-8000-000000000021', owner_id: USER_A, title: 'SECRET-NOTE', content: 'SECRET-NOTE-BODY' }],
  };
}

function world({ failTables = [], throwTables = [], tables = seed(), env: envOverride = {} } = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const name = url.pathname.split('/').pop();
    const query = Object.fromEntries(url.searchParams);
    calls.push({ method: init.method, name, query });
    if (throwTables.includes(name)) throw new Error('연결 실패');
    if (failTables.includes(name)) return new Response('{}', { status: 500 });
    const rows = tables[name];
    if (!rows) return new Response('{}', { status: 404 });
    const filters = Object.entries(query).filter(([key, value]) => !['select', 'limit', 'order'].includes(key) && value.startsWith('eq.'));
    const hit = rows.filter((row) => filters.every(([key, value]) => String(row[key]) === value.slice(3)));
    const limited = query.limit ? hit.slice(0, Number(query.limit)) : hit;
    const columns = query.select ? query.select.split(',') : null;
    return Response.json(limited.map((row) => (columns ? Object.fromEntries(columns.map((key) => [key, row[key]])) : row)));
  };
  const env = { SUPABASE_URL: 'https://example-project.supabase.co', SUPABASE_SECRET_KEY: STORE_VALUE, ...envOverride };
  const tokens = {
    'Bearer tokenA.aaa.aaa': { kind: 'student', userId: USER_A },
    'Bearer tokenB.bbb.bbb': { kind: 'student', userId: USER_B },
    'Bearer judgeA.aaa.aaa': { kind: 'judge', userId: USER_A, runId: 'run', identity: 'a' },
  };
  const verify = async (authorization) => tokens[authorization] ?? null;
  const now = () => NOW;
  const api = createOpsApi({ verify, env, fetchImpl, now, deviceCheck: createDeviceCheck({ env, fetchImpl, now }) });
  const call = async (method, { token, cookie, handler = api.summary } = {}) => {
    const res = fakeResponse();
    const headers = {};
    if (token) headers.authorization = `Bearer ${token}`;
    if (cookie) headers.cookie = `${DEVICE_COOKIE}=${cookie}`;
    await handler({ method, url: '/api/ops/summary', headers }, res);
    return res;
  };
  const warn = mock.method(console, 'warn', () => {});
  const error = mock.method(console, 'error', () => {});
  return { tables, calls, api, call, A: 'tokenA.aaa.aaa', B: 'tokenB.bbb.bbb', J: 'judgeA.aaa.aaa', env,
    logs: () => [...warn.mock.calls, ...error.mock.calls].map((entry) => entry.arguments.join(' ')).join('\n'),
    done: () => { warn.mock.restore(); error.mock.restore(); } };
}
const asA = (w, options = {}) => w.call('GET', { token: w.A, cookie: COOKIE_APPROVED, ...options });

test('요약의 수치는 본인 기록 원본의 집계와 같고 가린 기록의 건수와도 맞는다', async () => {
  const w = world();
  try {
    const res = await asA(w);
    assert.equal(res.statusCode, 200);
    assert.equal(res.headers['cache-control'], 'no-store');
    const body = res.body;
    assert.deepEqual(Object.keys(body).sort(), ['decider', 'detection', 'notRun', 'readAt', 'recovery', 'revocation', 'schema']);
    assert.equal(body.schema, OPS_SCHEMA);
    assert.equal(body.readAt, new Date(NOW).toISOString());

    // 회수 상태: 기기 승인 표의 원본 집계와 같다
    const mine = w.tables.vault_devices.filter((row) => row.owner_id === USER_A);
    const expectedCounts = { pending: 2, approved: 1, denied: 1, revoked: 1, other: 0 };
    assert.deepEqual(body.revocation.counts, expectedCounts);
    assert.equal(body.revocation.total, mine.length);
    assert.equal(body.revocation.total, Object.values(body.revocation.counts).reduce((sum, value) => sum + value, 0));
    assert.equal(body.revocation.records.length, mine.length);
    assert.equal(body.revocation.truncated, false);
    assert.deepEqual(body.revocation.records.map((record) => record.ref), ['a2a2a2a2', 'a3a3a3a3', 'a5a5a5a5', 'a4a4a4a4', 'a1a1a1a1'], '요청 시각이 최근인 순서');
    for (const record of body.revocation.records) {
      const row = mine.find((item) => item.id.startsWith(record.ref));
      assert.ok(row, record.ref);
      assert.equal(record.createdAt, new Date(row.created_at).toISOString());
      assert.equal(record.decidedAt, row.decided_at ? new Date(row.decided_at).toISOString() : null);
      assert.equal(record.expiresAt, row.expires_at ? new Date(row.expires_at).toISOString() : null);
      assert.equal(record.status, row.status, '상태는 저장된 값 그대로이고 현재 시각으로 만든 상태가 아니다');
    }
    assert.deepEqual(Object.fromEntries(Object.keys(expectedCounts).map((state) => [state, body.revocation.records.filter((record) => record.status === state).length])), expectedCounts);
    assert.deepEqual(body.revocation.enforcement.run, false);
    assert.ok(!('expired' in body.revocation.counts), '현재 시각으로 계산한 만료 상태를 만들지 않는다');

    // 복구 버전: 사본과 복원 기록의 원본 집계와 같다
    const backups = w.tables.vault_notes_backup.filter((row) => row.owner_id === USER_A);
    const restores = w.tables.vault_restore_audit.filter((row) => row.owner_id === USER_A);
    assert.equal(body.recovery.backups.total, backups.length);
    assert.equal(body.recovery.backups.records.length, backups.length);
    assert.equal(body.recovery.restores.total, restores.length);
    assert.equal(body.recovery.restores.records.length, restores.length);
    assert.deepEqual(body.recovery.restores.records.map((record) => `${record.ref}:${record.hash12}`),
      ['c1c1c1c1:444444444444', 'c2c2c2c2:222222222222', 'c1c1c1c1:111111111111'], '최근 복원이 먼저');
    for (const record of body.recovery.restores.records) assert.equal(record.outcome, 'restored');
    assert.equal(body.recovery.policySnapshot.confirmed, false);
  } finally { w.done(); }
});

test('판정기 규칙과 탐지 기준은 코드에서 읽은 정의로만 알리고 계산한 값과 결과를 싣지 않는다', async () => {
  const w = world();
  try {
    const { decider, detection, notRun } = (await asA(w)).body;
    assert.deepEqual(Object.keys(decider).sort(), ['kind', 'results', 'ruleIds', 'source']);
    assert.equal(decider.kind, 'definition');
    assert.equal(decider.source, 'code');
    assert.deepEqual(decider.ruleIds, [...RULE_IDS]);
    for (const computed of ['ruleCount', 'zoneRouteCount', 'allowedRouteCount', 'policyDigest', 'confirmed']) {
      assert.ok(!(computed in decider), `${computed}: 서버가 계산해 만든 값은 싣지 않는다`);
    }
    assert.equal(decider.results.recorded, false);
    assert.deepEqual(Object.keys(detection).sort(), ['events', 'kind', 'rule', 'source']);
    assert.equal(detection.kind, 'definition');
    assert.deepEqual(detection.rule, { windowSeconds: 600, threshold: 120, reasonCode: 'burst_read' });
    assert.deepEqual(detection.rule, { ...DETECTION_RULE });
    assert.equal(detection.events.recorded, false);
    assert.ok(!('confirmed' in detection));
    assert.deepEqual(notRun.map((item) => item.id), ['decision_results', 'detection_events', 'revocation_enforcement', 'policy_snapshot', 'attack_verdict']);
    assert.match(notRun.at(-1).text, /통과 근거가 아닙니다/u);
    // 정책 전체가 코드와 같은지 직접 확인할 수 있게 현재 정책을 읽어 규칙 이름만 대조한다
    assert.deepEqual(decider.ruleIds, describePolicy().ruleIds);
    assert.ok(config.allowedRoutes.length > 0);
  } finally { w.done(); }
});

test('응답에는 메모 제목·내용, 쿠키 값, 해시 원문, 승인 코드, 소유자·사용자 번호, 전체 번호가 없다', async () => {
  const w = world();
  try {
    const res = await asA(w);
    const text = `${JSON.stringify(res.body)}\n${w.logs()}`;
    const secrets = [
      'SECRET-', STORE_VALUE, COOKIE_APPROVED, COOKIE_PENDING, sha(COOKIE_APPROVED), sha(COOKIE_PENDING), 'ABCD2345', USER_A, USER_B, 'tokenA', 'Bearer',
      ...Object.values(w.tables).flat().flatMap((row) => [row.id, row.note_id, row.owner_id, row.content_sha256, row.secret_sha256]).filter((value) => typeof value === 'string' && value.length > 12),
    ];
    for (const secret of secrets) assert.ok(!text.includes(secret), secret.slice(0, 16));
    assert.doesNotMatch(text, /[0-9a-f]{13,}/iu, '12자를 넘는 16진수 문자열 없음');
  } finally { w.done(); }
});

test('본인 기록만 읽는다: 모든 조회에 소유자 조건이 있고 다른 계정의 기록은 수치에 없다', async () => {
  const w = world();
  try {
    const mine = (await asA(w)).body;
    const other = await w.call('GET', { token: w.B });
    assert.equal(other.statusCode, 403, 'B는 승인된 기기 쿠키가 없어 거부');
    assert.equal(mine.revocation.total, 5);
    assert.equal(mine.recovery.backups.total, 2);
    assert.equal(mine.recovery.restores.total, 3);
    assert.ok(!JSON.stringify(mine).includes('b1b1b1b1') && !JSON.stringify(mine).includes('d1d1d1d1'));
    const reads = w.calls.filter((call) => call.name !== 'vault_devices' || call.query.select !== 'id,owner_id,status,request_code,expires_at');
    assert.ok(reads.length >= 3);
    for (const call of w.calls.filter((item) => ['vault_notes_backup', 'vault_restore_audit'].includes(item.name)
      || (item.name === 'vault_devices' && item.query.select.includes('created_at')))) {
      assert.equal(call.query.owner_id, `eq.${USER_A}`, call.name);
    }
  } finally { w.done(); }
});

test('읽기 전용이다: GET만 보내고 메모 표는 읽지 않으며 제목·내용·기기 해시·승인 코드를 요청하지 않는다', async () => {
  const w = world();
  try {
    await asA(w);
    assert.ok(w.calls.length >= 4);
    assert.deepEqual([...new Set(w.calls.map((call) => call.method))], ['GET']);
    assert.ok(!w.calls.some((call) => call.name === 'vault_notes'), '메모 표를 읽지 않음');
    const selects = w.calls.filter((call) => call.query.select).map((call) => `${call.name}:${call.query.select}`);
    const summaryReads = w.calls.filter((call) => ['vault_notes_backup', 'vault_restore_audit'].includes(call.name) || call.query.select?.includes('created_at'));
    for (const call of summaryReads) {
      assert.doesNotMatch(call.query.select, /title|content(?!_sha256)|secret_sha256|request_code|owner_id|decided_by/u, `${call.name}:${call.query.select}`);
    }
    assert.ok(selects.length >= 4);
    assert.doesNotMatch(readFileSync(`${root}src/ops-api.mjs`, 'utf8'), /method: '(?:POST|PUT|PATCH|DELETE)'|\.insert\(|writeFile|appendFile/u);
  } finally { w.done(); }
});

test('한 표를 읽지 못하면 그 구역만 미확인이고 나머지는 확인된 값 그대로 보인다', async () => {
  for (const options of [{ failTables: ['vault_restore_audit'] }, { throwTables: ['vault_notes_backup'] }, { failTables: ['vault_devices'] }]) {
    const w = world(options);
    try {
      // 기기 검사도 기기 표를 읽으므로 기기 표가 실패하면 자료 API처럼 닫힌다
      const res = await asA(w);
      if (options.failTables?.includes('vault_devices')) { assert.equal(res.statusCode, 403); continue; }
      assert.equal(res.statusCode, 200, JSON.stringify(options));
      const { revocation, recovery, decider, detection } = res.body;
      assert.equal(decider.kind, 'definition');
      assert.equal(detection.kind, 'definition');
      assert.equal(revocation.confirmed, true);
      assert.equal(revocation.total, 5);
      if (options.failTables) {
        assert.equal(recovery.restores.confirmed, false);
        assert.equal(recovery.restores.total, undefined);
        assert.equal(recovery.backups.confirmed, true);
        assert.equal(recovery.backups.total, 2);
      } else {
        assert.equal(recovery.backups.confirmed, false);
        assert.equal(recovery.restores.confirmed, true);
        assert.equal(recovery.restores.total, 3);
      }
      assert.equal(recovery.confirmed, true);
    } finally { w.done(); }
  }
  const none = world({ tables: { ...seed(), vault_notes_backup: undefined, vault_restore_audit: undefined } });
  try {
    const res = await asA(none);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.recovery.confirmed, false);
    assert.equal(res.body.recovery.backups.confirmed, false);
    assert.equal(res.body.recovery.restores.confirmed, false);
    assert.equal(res.body.revocation.confirmed, true);
  } finally { none.done(); }
});

test('기록이 읽기 한도를 넘으면 truncated로 알리고 총수와 가린 기록은 같은 100건이다', async () => {
  const tables = seed();
  for (let index = 0; index < 120; index += 1) {
    tables.vault_restore_audit.push({ id: 100 + index, note_id: `f${String(index).padStart(7, '0')}-0000-4000-8000-000000000099`, owner_id: USER_A,
      content_sha256: hex('5'), outcome: 'restored', restored_at: stamp(-1000 + index) });
  }
  const w = world({ tables });
  try {
    const { restores } = (await asA(w)).body.recovery;
    assert.equal(restores.total, FETCH_LIMIT);
    assert.equal(restores.truncated, true);
    assert.equal(restores.records.length, restores.total, '화면 수치와 가린 기록의 줄 수가 같다');
    assert.equal(restores.records.length, RECORD_LIMIT);
    assert.equal(RECORD_LIMIT, FETCH_LIMIT);
    // 읽기 요청은 한도보다 1건 더 요청해 한도를 넘는지 알아낸다
    assert.ok(w.calls.filter((call) => call.name === 'vault_restore_audit').every((call) => call.query.limit === String(FETCH_LIMIT + 1)));
  } finally { w.done(); }
});

test('기록 수가 0, 1, 10, 11, 14, 100, 101건이어도 총수, 상태별 수, 가린 기록 줄 수, 원본 행 수가 같다', async () => {
  for (const extra of [0, 1, 10, 11, 14, 100, 101]) {
    const tables = seed();
    const mineApproved = tables.vault_devices.filter((row) => row.owner_id === USER_A && row.status === 'approved' && row.secret_sha256 === sha(COOKIE_APPROVED));
    tables.vault_devices = [...mineApproved, ...tables.vault_devices.filter((row) => row.owner_id === USER_B)];
    tables.vault_restore_audit = tables.vault_restore_audit.filter((row) => row.owner_id === USER_B);
    tables.vault_notes_backup = [];
    for (let index = 0; index < extra; index += 1) {
      tables.vault_devices.push({ id: `e${String(index).padStart(7, '0')}-0000-4000-8000-000000000001`, owner_id: USER_A, secret_sha256: sha(`x${index}`),
        status: ['pending', 'denied', 'revoked'][index % 3], request_code: 'ABCD2345', created_at: stamp(-index), decided_at: null, expires_at: stamp(index % 2 ? 10 : -10) });
      tables.vault_restore_audit.push({ id: 1000 + index, note_id: `d${String(index).padStart(7, '0')}-0000-4000-8000-000000000002`, owner_id: USER_A,
        content_sha256: hex('6'), outcome: 'restored', restored_at: stamp(-index) });
      tables.vault_notes_backup.push({ id: `c${String(index).padStart(7, '0')}-0000-4000-8000-000000000003`, owner_id: USER_A, title: 'SECRET-T', content: 'SECRET-B',
        content_sha256: hex('7'), backed_up_at: stamp(-index) });
    }
    const w = world({ tables });
    try {
      const { revocation, recovery } = (await asA(w)).body;
      const rawDevices = tables.vault_devices.filter((row) => row.owner_id === USER_A).length;
      const lists = [
        ['기기', revocation, rawDevices],
        ['사본', recovery.backups, extra],
        ['복원', recovery.restores, extra],
      ];
      for (const [label, section, rawCount] of lists) {
        const expectedTotal = Math.min(rawCount, FETCH_LIMIT);
        assert.equal(section.total, expectedTotal, `${label} ${extra}: 총수`);
        assert.equal(section.records.length, section.total, `${label} ${extra}: 가린 기록 줄 수`);
        assert.equal(section.truncated, rawCount > FETCH_LIMIT, `${label} ${extra}: truncated`);
      }
      assert.equal(Object.values(revocation.counts).reduce((sum, value) => sum + value, 0), revocation.total, `기기 ${extra}: 상태별 수의 합`);
      for (const state of Object.keys(revocation.counts)) {
        assert.equal(revocation.counts[state], revocation.records.filter((record) => record.status === state).length, `기기 ${extra}: ${state}`);
      }
    } finally { w.done(); }
  }
});

test('작전실은 로그인과 기기 승인을 요구한다: 승인 전·쿠키 없음·저장소 오류는 닫고 judge와 DEVICE_GATE=off는 통과한다', async () => {
  const w = world();
  try {
    assert.equal((await w.call('GET', {})).statusCode, 401);
    assert.equal((await w.call('GET', { token: 'forged.aaa.bbb' })).statusCode, 401);
    for (const options of [{ token: w.A }, { token: w.A, cookie: COOKIE_PENDING }, { token: w.A, cookie: 'c'.repeat(43) }, { token: w.B, cookie: COOKIE_APPROVED }]) {
      const res = await w.call('GET', options);
      assert.equal(res.statusCode, 403, JSON.stringify(options));
      assert.deepEqual(res.body, { error: '기기 승인이 필요합니다.', code: 'device_not_approved' });
    }
    assert.equal((await w.call('GET', { token: w.J })).statusCode, 200, 'judge 종류는 엔진이 기기를 검증한다고 보고 통과');
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      const res = await w.call(method, { token: w.A, cookie: COOKIE_APPROVED });
      assert.equal(res.statusCode, 405, method);
      assert.equal(res.headers.allow, 'GET');
    }
    const open = world({ env: { DEVICE_GATE: 'off' } });
    try { assert.equal((await open.call('GET', { token: open.A })).statusCode, 200); } finally { open.done(); }
    const noEnv = world({ env: { SUPABASE_URL: '' } });
    try { assert.equal((await noEnv.call('GET', { token: noEnv.A, cookie: COOKIE_APPROVED })).statusCode, 500); } finally { noEnv.done(); }
  } finally { w.done(); }
});

test('운영 연결: 운영용 작전실 API는 기기 검사가 연결돼 있고 경로 파일이 요약 함수를 내보낸다', async () => {
  assert.equal(opsApi.gated, true);
  assert.equal(createOpsApi().gated, false, '시험용 기본값은 검사가 없다');
  assert.ok(existsSync(`${root}api/ops/summary.mjs`));
  assert.equal((await import('../api/ops/summary.mjs')).default, opsApi.summary);
  const functions = ['api/auth/login.mjs', 'api/auth/logout.mjs', 'api/auth/refresh.mjs', 'api/notes/index.mjs', 'api/notes/[id].mjs', 'api/notes/[id]/restore.mjs',
    'api/device/request.mjs', 'api/device/status.mjs', 'api/device/approve.mjs', 'api/ops/summary.mjs'];
  assert.ok(functions.every((path) => existsSync(`${root}${path}`)));
  assert.ok(functions.length <= 12, 'Vercel 무료 한도 12개 이내');
  // 판정기와 허용 경로는 바꾸지 않았다: 작전실 경로는 자료 API가 아니라서 allowedRoutes에 없다
  assert.ok(!config.allowedRoutes.some((route) => route.includes('/ops')));
});
