import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { decide } from '../src/decider.mjs';
import { currentPolicy } from '../src/policy-diff.mjs';
import { decideWithPolicy } from '../src/policy-eval.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const { normal, suspicious } = fixtureRequests();
const pick = list => list[Math.floor(Math.random() * list.length)];
const clone = value => JSON.parse(JSON.stringify(value));

function randomRequest() {
  const signals = pick([normal.signals, suspicious.signals, undefined, null, { source: 'none', network: 'unusual', hour: 3 },
    { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 5 }, { source: 'judge_fixture', network: 'usual', hour: 14 }]);
  return {
    ...normal, requestId: randomUUID(), signals,
    deviceRegistered: pick([true, true, false, undefined, 'true']),
    service: pick(['notes', 'notices', 'instructor', 'constructor', '__proto__', 'toString', 'x', 7, undefined]),
    method: pick(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'get', undefined]),
    route: pick(['GET /notes/:id', 'PUT /notes/:id', 'DELETE /notes/:id', 'GET /notes', 'GET /notices', 'GET /notices/:id', 'POST /notices', 'GET /instructor', 'x', 3, undefined]),
    path: pick(['/notes/demo', '/notes/export', '/notes/Mine', '/notes/..', '/notes/a%2e', '/notes', '/notices', '/notices/abc', '/instructor/abc', '/', '', 7, undefined]),
    recentEvents: pick([[], suspicious.recentEvents, [{ kind: 'risk_signal', ageSeconds: 301, count: 50 }], undefined, [{ kind: 'x' }]]),
    stepUp: pick([{ verified: false, authAgeSeconds: null }, { verified: true, authAgeSeconds: 60 }, { verified: true, authAgeSeconds: 901 }, undefined, null]),
  };
}

test('기본 정책으로 돌린 평가기는 decide()와 무작위 요청 4000건에서 완전히 같은 응답을 낸다', async () => {
  const policy = currentPolicy();
  for (let index = 0; index < 4000; index += 1) {
    const request = randomRequest();
    assert.deepEqual(decideWithPolicy(policy, request), await decide(request), JSON.stringify(request));
  }
});

test('고정 요청에서도 같다: 정상은 allow, 복합 이상은 step_up, 재확인은 allow, 미등록은 deny', async () => {
  const policy = currentPolicy();
  for (const request of [normal, suspicious, { ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } }, { ...normal, deviceRegistered: false }]) {
    assert.deepEqual(decideWithPolicy(policy, request), await decide(request));
  }
  assert.equal(decideWithPolicy(policy, suspicious).decision, 'step_up');
});

test('객체 기본 속성 이름의 서비스는 오류 없이 거부한다', async () => {
  for (const service of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf']) {
    const request = { ...normal, requestId: randomUUID(), service, path: '/notes/demo', route: 'GET /notes/:id' };
    const result = await decide(request);
    assert.equal(result.decision, 'deny', service);
    assert.equal(result.reasonCode, 'route_not_allowed', service);
    assert.deepEqual(decideWithPolicy(currentPolicy(), request), result, service);
  }
});

test('정책 값을 바꾸면 평가 결과가 바뀐다: 침해된 정책은 전체 목록을 허용한다', () => {
  const breached = clone(currentPolicy());
  breached.zoneRoutes.notes.push('GET /notes');
  const listRequest = { ...normal, requestId: randomUUID(), service: 'notes', method: 'GET', route: 'GET /notes', path: '/notes' };
  assert.equal(decideWithPolicy(currentPolicy(), listRequest).decision, 'deny');
  assert.equal(decideWithPolicy(breached, listRequest).decision, 'allow');
});

test('잘못된 정책은 거부하지 않고 오류로 알린다', () => {
  assert.throws(() => decideWithPolicy({ ruleIds: ['a'] }, normal), TypeError);
  assert.throws(() => decideWithPolicy(undefined, normal), TypeError);
});
