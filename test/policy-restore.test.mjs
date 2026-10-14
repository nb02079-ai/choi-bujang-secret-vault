import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createNotesApi } from '../src/notes-api.mjs';
import { PolicyCopyError, SNAPSHOT_SCHEMA, currentPolicy, snapshotDigest } from '../src/policy-diff.mjs';
import { decideWithPolicy } from '../src/policy-eval.mjs';
import { applyRestore, loadTestPolicy, parseScope, planApply, renderApplyPlan } from '../src/policy-restore.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const dir = mkdtempSync(join(tmpdir(), 'policy-restore-'));
const { normal } = fixtureRequests();
const clone = value => JSON.parse(JSON.stringify(value));
const sha = path => (existsSync(path) ? createHash('sha256').update(readFileSync(path)).digest('hex') : 'absent');
let counter = 0;
const fresh = name => join(dir, `${name}-${counter += 1}`);

const base = currentPolicy();
const snapshotFile = path => {
  const body = { schema: SNAPSHOT_SCHEMA, version: 'pre-breach-1', policy: base };
  writeFileSync(path, JSON.stringify({ ...body, sha256: snapshotDigest(body) }));
  return { path, sha256: snapshotDigest(body) };
};
// 침해 상태: 전체 목록 경로 추가, 기능 이름 비움. 공지 쪽의 다른 변경은 보존 대상입니다.
const breached = () => {
  const policy = clone(base);
  policy.zoneRoutes.notes.push('GET /notes');
  policy.functionNames = [];
  policy.zoneRoutes.notices.push('GET /notices/:id/pin');
  return policy;
};
const setup = () => {
  const snapshot = snapshotFile(fresh('snapshot.json'));
  const testPolicyPath = fresh('test-policy.json');
  const auditPath = fresh('audit.log');
  writeFileSync(testPolicyPath, JSON.stringify(breached()));
  return { snapshot, testPolicyPath, auditPath };
};
const args = (s, extra = {}) => ({ snapshotPath: s.snapshot.path, expectedSha256: s.snapshot.sha256, only: 'zoneRoutes.notes,functionNames',
  testPolicyPath: s.testPolicyPath, auditPath: s.auditPath, ...extra });
const request = (service, method, route, path) => ({ ...normal, requestId: randomUUID(), service, method, route, path });
const codeOf = action => { try { action(); } catch (error) { assert.ok(error instanceof PolicyCopyError, String(error)); return error.code; } return 'no_error'; };

const NOTE_A = '11111111-1111-4111-8111-111111111111';
const USER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const STORE_VALUE = [['sb', ['sec', 'ret'].join(''), ''].join('_'), 'restore_value'].join('');
function apiFixture() {
  const rows = [{ id: NOTE_A, owner_id: USER_A, title: 'A의 메모', content: 'a' }];
  const fetchImpl = async (url) => {
    const query = Object.fromEntries(url.searchParams);
    const eq = field => (query[field]?.startsWith('eq.') ? query[field].slice(3) : undefined);
    const hit = rows.filter(row => (eq('id') === undefined || row.id === eq('id')) && (eq('owner_id') === undefined || row.owner_id === eq('owner_id')));
    return Response.json(hit.map(row => Object.fromEntries(query.select.split(',').map(key => [key, row[key]]))));
  };
  const tokens = { 'Bearer tokenA.aaa.aaa': { kind: 'student', userId: USER_A }, 'Bearer tokenB.bbb.bbb': { kind: 'student', userId: USER_B } };
  const api = createNotesApi({ verify: async authorization => tokens[authorization] ?? null, fetchImpl,
    env: { SUPABASE_URL: 'https://example-project.supabase.co', SUPABASE_SECRET_KEY: STORE_VALUE } });
  return async (token) => {
    const res = { headers: {}, statusCode: 0, body: undefined, setHeader() {}, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
    await api.item({ method: 'GET', url: `/api/notes/${NOTE_A}`, headers: { authorization: `Bearer ${token}` } }, res);
    return res;
  };
}

test('침해된 시험 정책에서는 B의 전체 목록·내보내기 요청이 허용된다 (복원 전 확인)', () => {
  const policy = breached();
  assert.equal(decideWithPolicy(policy, request('notes', 'GET', 'GET /notes', '/notes')).decision, 'allow');
  assert.equal(decideWithPolicy(policy, request('notes', 'GET', 'GET /notes/:id', '/notes/export')).decision, 'allow');
  assert.equal(decideWithPolicy(policy, request('notes', 'GET', 'GET /notes/:id', `/notes/${NOTE_A}`)).decision, 'allow');
});

test('미리보기는 복원할 버전, 범위, 바뀔 항목, 확인 토큰을 보이고 아무것도 쓰지 않는다', () => {
  const s = setup();
  const before = [sha(s.testPolicyPath), sha(s.auditPath), sha(s.snapshot.path)];
  const plan = planApply(args(s));
  const text = renderApplyPlan(plan);
  const lines = text.split('\n');
  assert.equal(lines[0], '복원할 버전: pre-breach-1');
  assert.equal(lines[2], '복원 범위: functionNames, zoneRoutes.notes');
  assert.match(lines[3], /^바뀔 항목: \d+개$/u);
  assert.match(text, /\[복원하면 삭제\] zoneRoutes\.notes: "GET \/notes"/u);
  assert.match(text, /\[복원하면 추가\] functionNames: "export"/u);
  assert.match(text, /그대로 두는 항목: 1개/u, '범위 밖 공지 변경은 그대로 둠');
  assert.match(text, new RegExp(`확인 토큰: ${plan.token}`, 'u'));
  assert.deepEqual([sha(s.testPolicyPath), sha(s.auditPath), sha(s.snapshot.path)], before);
  assert.equal(existsSync(s.auditPath), false);
});

test('확인 토큰이 없거나 틀리면 쓰지 않는다', () => {
  const s = setup();
  const before = sha(s.testPolicyPath);
  const token = planApply(args(s)).token;
  for (const confirm of [undefined, null, '', 'wrongtoken00', token.toUpperCase(), `${token}x`, 7]) {
    assert.equal(codeOf(() => applyRestore(args(s, { confirm }))), 'confirm_mismatch', String(confirm));
  }
  assert.equal(sha(s.testPolicyPath), before);
  assert.equal(existsSync(s.auditPath), false);
});

test('확인 후 복원: B의 A 자료 요청은 다시 거부되고 A 정상 요청은 유지된다', async () => {
  const s = setup();
  const plan = planApply(args(s));
  const result = applyRestore(args(s, { confirm: plan.token, now: () => new Date('2026-10-14T09:00:00Z') }));
  assert.equal(result.applied, true);
  const policy = loadTestPolicy(s.testPolicyPath);
  // B의 전체 목록, 내보내기, 기능 이름 경로는 거부
  for (const [route, path] of [['GET /notes', '/notes'], ['GET /notes/:id', '/notes/export'], ['GET /notes/:id', '/notes/mine'], ['GET /notes/:id', '/notes/admin']]) {
    const verdict = decideWithPolicy(policy, request('notes', 'GET', route, path));
    assert.equal(verdict.decision, 'deny', path);
    assert.equal(verdict.reasonCode, 'route_not_allowed', path);
  }
  // A의 정상 요청은 유지
  for (const method of ['GET', 'PUT', 'DELETE']) {
    assert.equal(decideWithPolicy(policy, request('notes', method, `${method} /notes/:id`, `/notes/${NOTE_A}`)).decision, 'allow', method);
  }
  assert.equal(decideWithPolicy(policy, request('notices', 'GET', 'GET /notices', '/notices')).decision, 'allow');
  // 다른 서비스 규칙(공지)에 지정하지 않은 변경은 그대로 보존
  assert.ok(policy.zoneRoutes.notices.includes('GET /notices/:id/pin'));
  assert.deepEqual(policy.zoneRoutes.notes, base.zoneRoutes.notes);
  assert.deepEqual(policy.functionNames, base.functionNames);
  assert.equal(decideWithPolicy(policy, request('notices', 'GET', 'GET /notices/:id/pin', '/notices/abc/pin')).decision, 'allow');
  // 자료 API: B가 A의 메모를 직접 요청하면 404, A는 정상 (정책과 별개로 소유자 재대조가 막음)
  const warnings = mock.method(console, 'warn', () => {});
  try {
    const call = apiFixture();
    const forB = await call('tokenB.bbb.bbb');
    assert.equal(forB.statusCode, 404);
    assert.ok(!JSON.stringify(forB.body).includes('A의 메모'));
    const forA = await call('tokenA.aaa.aaa');
    assert.equal(forA.statusCode, 200);
    assert.equal(forA.body.title, 'A의 메모');
  } finally { warnings.mock.restore(); }
});

test('감사 이력은 덧붙이기만 한다: 기존 줄은 그대로이고 값 원문은 남지 않는다', () => {
  const s = setup();
  const existing = '{"event":"earlier","n":1}\n{"event":"earlier","n":2}';
  writeFileSync(s.auditPath, existing);
  const first = applyRestore(args(s, { confirm: planApply(args(s)).token, now: () => new Date('2026-10-14T09:00:00Z') }));
  const afterFirst = readFileSync(s.auditPath, 'utf8');
  assert.ok(afterFirst.startsWith(existing));
  assert.equal(afterFirst.trim().split('\n').length, 3);
  const entry = JSON.parse(afterFirst.trim().split('\n')[2]);
  assert.deepEqual(Object.keys(entry).sort(), ['at', 'changes', 'event', 'scope', 'snapshot', 'token', 'version']);
  assert.equal(entry.event, 'policy_restore');
  assert.equal(entry.at, '2026-10-14T09:00:00.000Z');
  assert.equal(entry.snapshot, first.plan.digest.slice(0, 12));
  assert.ok(entry.changes.length > 0 && entry.changes.every(change => Object.keys(change).sort().join() === 'count,kind,path' && change.count >= 1));
  assert.ok(!afterFirst.includes('GET /notes'), '값 원문은 감사 이력에 쓰지 않음');
  // 다시 침해된 뒤 한 번 더 복원해도 이전 줄은 그대로
  writeFileSync(s.testPolicyPath, JSON.stringify(breached()));
  applyRestore(args(s, { confirm: planApply(args(s)).token }));
  const afterSecond = readFileSync(s.auditPath, 'utf8');
  assert.ok(afterSecond.startsWith(afterFirst));
  assert.equal(afterSecond.trim().split('\n').length, 4);
});

test('범위 안에서 이미 같으면 아무것도 바꾸지 않고 감사 줄도 만들지 않는다', () => {
  const s = setup();
  applyRestore(args(s, { confirm: planApply(args(s)).token }));
  const before = [sha(s.testPolicyPath), sha(s.auditPath)];
  const again = applyRestore(args(s, { confirm: 'anything0000' }));
  assert.equal(again.applied, false);
  assert.match(renderApplyPlan(again.plan), /바뀔 항목: 없음/u);
  assert.deepEqual([sha(s.testPolicyPath), sha(s.auditPath)], before);
});

test('복원 범위(--only)가 없거나 전체이거나 잘못되면 중단하고 아무것도 바꾸지 않는다', () => {
  const s = setup();
  const before = sha(s.testPolicyPath);
  for (const only of [undefined, '', 'all', 'ALL', 'unknownArea', 'zoneRoutes.a.b', '__proto__', 'zoneRoutes,', '../x', 'zoneRoutes.notes;rm', []]) {
    assert.equal(codeOf(() => parseScope(only)), 'only_invalid', String(only));
    assert.equal(codeOf(() => applyRestore(args(s, { only, confirm: 'x' }))), 'only_invalid', String(only));
  }
  assert.equal(sha(s.testPolicyPath), before);
});

test('사본 문제로 중단할 때 시험 정책과 감사 이력은 그대로이다', () => {
  const s = setup();
  const before = [sha(s.testPolicyPath), sha(s.auditPath)];
  const tampered = fresh('tampered.json');
  writeFileSync(tampered, JSON.stringify({ ...JSON.parse(readFileSync(s.snapshot.path, 'utf8')), policy: breached() }));
  const cases = {
    snapshot_missing: args(s, { snapshotPath: fresh('none.json') }),
    expected_missing: args(s, { expectedSha256: undefined }),
    expected_mismatch: args(s, { expectedSha256: 'e'.repeat(64) }),
    digest_mismatch: args(s, { snapshotPath: tampered }),
  };
  for (const [code, options] of Object.entries(cases)) {
    assert.equal(codeOf(() => applyRestore({ ...options, confirm: 'tokentoken00' })), code, code);
    assert.equal(codeOf(() => planApply(options)), code, `${code} 미리보기`);
  }
  assert.deepEqual([sha(s.testPolicyPath), sha(s.auditPath)], before);
});

test('시험 정책 파일이 없으면 현재 코드 정책에서 시작하고, 깨진 파일은 중단한다', () => {
  assert.deepEqual(loadTestPolicy(fresh('absent.json')), base);
  const broken = fresh('broken.json');
  writeFileSync(broken, '{ nope');
  assert.equal(codeOf(() => loadTestPolicy(broken)), 'test_policy_invalid');
  const wrongShape = fresh('shape.json');
  writeFileSync(wrongShape, JSON.stringify({ ...base, extra: [] }));
  assert.equal(codeOf(() => loadTestPolicy(wrongShape)), 'test_policy_invalid');
});

test('감사 이력을 쓸 수 없으면 시험 정책을 이전 상태로 되돌린다', () => {
  const s = setup();
  const before = sha(s.testPolicyPath);
  const blocker = fresh('blocker');
  writeFileSync(blocker, 'file');
  const auditPath = join(blocker, 'audit.log'); // 상위가 파일이라 만들 수 없음
  assert.equal(codeOf(() => applyRestore(args(s, { auditPath, confirm: planApply(args(s)).token }))), 'apply_failed');
  assert.equal(sha(s.testPolicyPath), before);
  // 감사 이력을 읽을 수 없으면 쓰기 전에 중단
  const unreadable = fresh('unreadable.log');
  mkdirSync(unreadable);
  assert.equal(codeOf(() => applyRestore(args(s, { auditPath: unreadable, confirm: planApply(args(s)).token }))), 'audit_unreadable');
  assert.equal(sha(s.testPolicyPath), before);
});

test('계획이 바뀌면 이전 확인 토큰은 쓸 수 없다', () => {
  const s = setup();
  const token = planApply(args(s)).token;
  const changed = breached();
  changed.zoneRoutes.notes.push('GET /notes/:id/all');
  writeFileSync(s.testPolicyPath, JSON.stringify(changed));
  assert.equal(codeOf(() => applyRestore(args(s, { confirm: token }))), 'confirm_mismatch');
});

test('운영 정책 파일은 바뀌지 않고, 소스에 네트워크·프로세스 호출이 없다', () => {
  const guarded = ['src/decider.mjs', 'aleph.config.json', 'src/policy-diff.mjs'].map(name => join(root, name));
  const before = guarded.map(sha);
  const s = setup();
  applyRestore(args(s, { confirm: planApply(args(s)).token }));
  assert.deepEqual(guarded.map(sha), before);
  for (const name of ['src/policy-restore.mjs', 'src/policy-eval.mjs']) {
    assert.doesNotMatch(readFileSync(join(root, name), 'utf8'), /\b(fetch|child_process|XMLHttpRequest|process\.env)\b/u, name);
  }
});

test('명령: 미리보기는 쓰지 않고, 토큰을 붙이면 복원하며, 틀린 토큰은 종료 코드 1이다', () => {
  const s = setup();
  const base_args = ['--snapshot', s.snapshot.path, '--expect-sha256', s.snapshot.sha256, '--only', 'zoneRoutes.notes,functionNames',
    '--test-policy', s.testPolicyPath, '--audit', s.auditPath];
  const run = list => spawnSync(process.execPath, [join(root, 'scripts/policy-restore.mjs'), ...list], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  const before = sha(s.testPolicyPath);
  const preview = run(base_args);
  assert.equal(preview.status, 0, preview.stderr);
  assert.match(preview.stdout, /^복원할 버전: pre-breach-1\n/u);
  const token = /확인 토큰: ([0-9a-f]{12})/u.exec(preview.stdout)?.[1];
  assert.ok(token);
  assert.equal(sha(s.testPolicyPath), before);
  const wrong = run([...base_args, '--confirm', 'ffffffffffff']);
  assert.equal(wrong.status, 1);
  assert.match(wrong.stderr, /^중단: .*confirm_mismatch/u);
  assert.doesNotMatch(wrong.stderr, /\n\s+at /u);
  assert.equal(sha(s.testPolicyPath), before);
  const done = run([...base_args, '--confirm', token]);
  assert.equal(done.status, 0, done.stderr);
  assert.match(done.stdout, /^복원 완료: \d+개 항목/u);
  assert.notEqual(sha(s.testPolicyPath), before);
  assert.equal(readFileSync(s.auditPath, 'utf8').trim().split('\n').length, 1);
  for (const list of [[], ['--snapshot'], [...base_args.slice(0, 4), '--only', 'all'], ['--force', 'yes']]) {
    const failed = run(list);
    assert.equal(failed.status, 1, list.join(' '));
    assert.match(failed.stderr, /^중단: /u);
  }
});
