import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { decide, RULE_IDS, ZONE_REASON_CODES } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const UUID = '11111111-1111-4111-8111-111111111111';
const { normal } = fixtureRequests();
const make = (service, method, route, path, patch = {}) => ({ ...normal, requestId: randomUUID(),
  service, method, route: `${method} ${route}`, path, ...patch });
const RESPONSE_KEYS = 'decision,reasonCode,requestId,ruleIds,schema';

async function expectDeny(request, reasonCode, ruleId, label) {
  const result = await decide(request);
  assert.equal(result.decision, 'deny', label);
  assert.equal(result.reasonCode, reasonCode, label);
  assert.deepEqual(result.ruleIds, [ruleId], label);
  assert.equal(Object.keys(result).sort().join(','), RESPONSE_KEYS);
  assert.equal(result.requestId, request.requestId);
}

test('규칙 이름: 이전 두 규칙을 앞에 유지하고 구역 규칙 세 개를 더한다', () => {
  assert.deepEqual([...RULE_IDS], ['device_registered', 'step_up_required',
    'zone_route_exact', 'zone_notice_read_only', 'zone_instructor_denied']);
});

test('자기 메모 한 건 읽기·수정·삭제는 허용이다', async () => {
  for (const method of ['GET', 'PUT', 'DELETE']) {
    const result = await decide(make('notes', method, '/notes/:id', `/notes/${UUID}`));
    assert.equal(result.decision, 'allow', method);
    assert.equal(result.reasonCode, 'approved');
  }
});

test('메모 ID 형식은 좁히지 않는다: UUID가 아니어도 허용이다', async () => {
  for (const id of ['demo', 'note-1', 'A1_b2.c3', '12345', 'x'.repeat(128)]) {
    assert.equal((await decide(make('notes', 'GET', '/notes/:id', `/notes/${id}`))).decision, 'allow', id);
  }
});

test('메모 전체 목록과 ID 없는 경로는 거부한다', async () => {
  await expectDeny(make('notes', 'GET', '/notes', '/notes'), ZONE_REASON_CODES.route, 'zone_route_exact', '목록');
  await expectDeny(make('notes', 'POST', '/notes', '/notes'), ZONE_REASON_CODES.route, 'zone_route_exact', '추가');
  await expectDeny(make('notes', 'GET', '/notes/:id', '/notes/'), ZONE_REASON_CODES.route, 'zone_route_exact', '빈 ID');
});

test('반 공지는 읽기만 허용하고 쓰기는 누구에게나 거부한다', async () => {
  assert.equal((await decide(make('notices', 'GET', '/notices', '/notices'))).decision, 'allow');
  assert.equal((await decide(make('notices', 'GET', '/notices/:id', `/notices/${UUID}`))).decision, 'allow');
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    for (const [route, path] of [['/notices', '/notices'], ['/notices/:id', `/notices/${UUID}`]]) {
      await expectDeny(make('notices', method, route, path), ZONE_REASON_CODES.zone, 'zone_notice_read_only', `${method} ${path}`);
    }
  }
});

test('강사 자료는 모든 요청을 거부한다', async () => {
  for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
    await expectDeny(make('instructor', method, '/instructor/:id', `/instructor/${UUID}`),
      ZONE_REASON_CODES.zone, 'zone_instructor_denied', method);
    await expectDeny(make('instructor', method, '/instructor', '/instructor'),
      ZONE_REASON_CODES.zone, 'zone_instructor_denied', `${method} 목록`);
  }
  // 서비스 이름을 바꿔 속여도 경로의 첫 칸이 강사 자료이면 거부한다.
  await expectDeny(make('notes', 'GET', '/notes/:id', '/instructor/abc'), ZONE_REASON_CODES.zone, 'zone_instructor_denied', '위장');
});

test('알 수 없는 서비스·경로·방식은 거부한다', async () => {
  const cases = [
    make('unknown', 'GET', '/notes/:id', '/notes/demo'),
    make('notes', 'PATCH', '/notes/:id', '/notes/demo'),
    make('notes', 'HEAD', '/notes/:id', '/notes/demo'),
    make('notes', 'get', '/notes/:id', '/notes/demo'),
    make('Notes', 'GET', '/notes/:id', '/notes/demo'),
    make('notes', 'GET', '/notes/:id/comments', '/notes/demo/comments'),
    make('notes', 'GET', '/notes/:id', '/notes/demo/'),
    make('notes', 'GET', '/notes/:id', '/NOTES/demo'),
    make('notes', 'GET', '/notes/:id', '/notes/demo/extra'),
    make('notes', 'GET', '/notes/:id', '/notices/demo'),
    make('notes', 'GET', '/notes/:id', '/notes/demo?x=1'),
    make('notes', 'GET', '/admin', '/admin'),
    make('notes', 'GET', '/notes/:id', undefined),
    { ...normal, route: undefined },
    { ...normal, service: 7 },
  ];
  for (const [index, request] of cases.entries()) {
    const result = await decide(request);
    assert.equal(result.decision, 'deny', `case ${index}`);
    assert.ok(Object.values(ZONE_REASON_CODES).includes(result.reasonCode), `case ${index}`);
  }
});

test('경로 변조와 기능 이름은 ID로 받지 않는다', async () => {
  for (const id of ['..', '.', 'a%2e%2e', '%2e%2e', 'a b', 'a\\b', 'a#b', 'export', 'Export', 'import', 'search', 'list', 'all', 'new', 'bulk', 'x'.repeat(129)]) {
    await expectDeny(make('notes', 'GET', '/notes/:id', `/notes/${id}`), ZONE_REASON_CODES.route, 'zone_route_exact', id);
  }
  await expectDeny(make('notes', 'GET', '/notes/:id', '/notes/a/../b'), ZONE_REASON_CODES.route, 'zone_route_exact', '이중 경로');
});

test('ID와 같은 깊이의 기능 이름은 모두 거부하고 일반 ID는 계속 허용한다', async () => {
  const names = ['me', 'mine', 'my', 'own', 'public', 'shared', 'share', 'everyone', 'users', 'user',
    'recent', 'latest', 'count', 'stats', 'summary', 'index', 'root',
    'admin', 'download', 'upload', 'backup', 'dump', 'sync', 'restore', 'batch', 'ADMIN', 'Shared'];
  for (const name of names) {
    for (const method of ['GET', 'PUT', 'DELETE']) {
      await expectDeny(make('notes', method, '/notes/:id', `/notes/${name}`), ZONE_REASON_CODES.route, 'zone_route_exact', `${method} ${name}`);
    }
    await expectDeny(make('notices', 'GET', '/notices/:id', `/notices/${name}`), ZONE_REASON_CODES.route, 'zone_route_exact', `공지 ${name}`);
  }
  for (const id of ['demo', 'note-1', 'meeting', 'adminx', 'my-note', UUID]) {
    assert.equal((await decide(make('notes', 'GET', '/notes/:id', `/notes/${id}`))).decision, 'allow', id);
  }
});

test('쿼리는 판정에 영향을 주지 않는다', async () => {
  const base = make('notes', 'GET', '/notes/:id', '/notes/demo');
  for (const patch of [{ queryLength: 0 }, { queryLength: 50 }, { queryLength: 9999, querySha256: 'f'.repeat(64) }]) {
    assert.equal((await decide({ ...base, ...patch })).decision, 'allow');
  }
});

test('이전 규칙은 그대로다: 미등록 기기는 구역보다 먼저 거부하고, 복합 이상은 추가 확인이다', async () => {
  const unregistered = await decide(make('notes', 'GET', '/notes/:id', '/notes/demo', { deviceRegistered: false }));
  assert.equal(unregistered.reasonCode, 'device_not_registered');
  assert.deepEqual(unregistered.ruleIds, ['device_registered']);
  const unregisteredList = await decide(make('notes', 'GET', '/notes', '/notes', { deviceRegistered: false }));
  assert.equal(unregisteredList.reasonCode, 'device_not_registered');
  const { suspicious } = fixtureRequests();
  assert.equal((await decide(suspicious)).decision, 'step_up');
  const reverified = await decide({ ...suspicious, requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 60 } });
  assert.equal(reverified.decision, 'allow');
  // 구역 거부는 복합 이상보다 먼저다: 목록 경로는 재확인 요청 대신 거부된다.
  await expectDeny({ ...suspicious, requestId: randomUUID(), route: 'GET /notes', path: '/notes' },
    ZONE_REASON_CODES.route, 'zone_route_exact', '이상 + 목록');
});

test('위조 값은 읽지 않는다: role·identity·geo 항목은 판정에 영향이 없다', async () => {
  const forged = { role: 'instructor', identity: { sub: 'x' }, device: { approval: true }, geo: { region: 'local' } };
  assert.equal((await decide(make('notes', 'GET', '/notes/:id', '/notes/demo', forged))).decision, 'allow');
  await expectDeny(make('notices', 'POST', '/notices', '/notices', forged), ZONE_REASON_CODES.zone, 'zone_notice_read_only', '강사 위조');
  await expectDeny(make('notes', 'GET', '/notes', '/notes', forged), ZONE_REASON_CODES.route, 'zone_route_exact', '목록 위조');
});

test('어떤 가상 요청에도 형식이 맞는 응답을 돌려주고 ruleIds는 RULE_IDS 안에 있다', async () => {
  const pick = list => list[Math.floor(Math.random() * list.length)];
  for (let i = 0; i < 400; i += 1) {
    const request = {
      ...normal, requestId: randomUUID(),
      deviceRegistered: pick([true, true, false, undefined]),
      service: pick(['notes', 'notices', 'instructor', 'x', 7, undefined]),
      method: pick(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'get', undefined]),
      route: pick(['GET /notes/:id', 'PUT /notes/:id', 'GET /notes', 'GET /notices', 'POST /notices', 'GET /instructor', 'x', 3, undefined]),
      path: pick(['/notes/demo', '/notes', '/notices', '/notices/abc', '/instructor/abc', '/notes/../x', '/', '', 7, undefined]),
    };
    const result = await decide(request);
    assert.equal(Object.keys(result).sort().join(','), RESPONSE_KEYS);
    assert.equal(result.schema, 'aleph.decision.v1');
    assert.equal(result.requestId, request.requestId);
    assert.ok(['allow', 'deny', 'step_up'].includes(result.decision));
    assert.match(result.reasonCode, /^[a-z][a-z0-9_]{0,63}$/u);
    assert.ok(result.ruleIds.length > 0 && result.ruleIds.every(id => RULE_IDS.includes(id)));
  }
});

test('복원 경로: POST /notes/:id/restore 한 가지만 허용하고, 그 밖의 복원·기능 경로는 거부한다', async () => {
  const restore = path => make('notes', 'POST', '/notes/:id/restore', path);
  for (const id of [UUID, 'demo', 'note-1']) {
    const result = await decide(restore(`/notes/${id}/restore`));
    assert.equal(result.decision, 'allow', id);
    assert.equal(result.reasonCode, 'approved', id);
  }
  // ID 자리의 restore, 깊이가 다른 경로, 다른 방식·서비스는 거부한다.
  for (const request of [
    restore('/notes/restore'), restore('/notes//restore'), restore(`/notes/${UUID}/restore/extra`), restore(`/notes/${UUID}/export`),
    restore('/notes/../restore'), restore(`/notes/export/restore`), restore(`/notes/${UUID}/Restore`),
    make('notes', 'GET', '/notes/:id/restore', `/notes/${UUID}/restore`), make('notes', 'PUT', '/notes/:id/restore', `/notes/${UUID}/restore`),
    make('notes', 'DELETE', '/notes/:id/restore', `/notes/${UUID}/restore`), make('notes', 'POST', '/notes/restore', '/notes/restore'),
    make('notices', 'POST', '/notes/:id/restore', `/notes/${UUID}/restore`), make('notices', 'POST', '/notices/:id/restore', `/notices/${UUID}/restore`),
    make('instructor', 'POST', '/notes/:id/restore', `/notes/${UUID}/restore`), make('constructor', 'POST', '/notes/:id/restore', `/notes/${UUID}/restore`),
  ]) {
    const result = await decide(request);
    assert.equal(result.decision, 'deny', `${request.service} ${request.method} ${request.path}`);
  }
});
