import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { decide, explainStepUp, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const fresh = (request, patch = {}) => ({ ...request, requestId: randomUUID(), ...patch });
const withSignals = (request, patch) => fresh(request, { signals: { ...request.signals, ...patch } });
const burst = count => [{ kind: 'risk_signal', ageSeconds: 60, count }];

test('규칙 이름: 기기 규칙을 유지하고 step_up_required를 더한다', () => {
  assert.deepEqual([...RULE_IDS], ['device_registered', 'step_up_required']);
});

test('정상 사건은 허용이다', async () => {
  const { normal } = fixtureRequests();
  const result = await decide(normal);
  assert.equal(result.decision, 'allow');
  assert.equal(result.reasonCode, 'approved');
  assert.deepEqual(explainStepUp(normal), { matched: false, reasons: [] });
});

test('정해진 복합 사건은 추가 확인이고 사유가 남는다', async () => {
  const { suspicious } = fixtureRequests();
  const result = await decide(suspicious);
  assert.equal(result.decision, 'step_up');
  assert.equal(result.reasonCode, 'step_up_required');
  assert.deepEqual(result.ruleIds, ['step_up_required']);
  assert.deepEqual(Object.keys(result).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  assert.deepEqual(explainStepUp(suspicious).reasons,
    ['odd_hour', 'unseen_network', 'burst_read', 'region_unusual']);
});

test('재확인이 있으면 허용하고, 오래되었거나 형식이 틀리면 다시 추가 확인이다', async () => {
  const { suspicious } = fixtureRequests();
  assert.equal((await decide(fresh(suspicious, { stepUp: { verified: true, authAgeSeconds: 60 } }))).decision, 'allow');
  assert.equal((await decide(fresh(suspicious, { stepUp: { verified: true, authAgeSeconds: 900 } }))).decision, 'allow');
  for (const stepUp of [
    { verified: true, authAgeSeconds: 901 },
    { verified: true, authAgeSeconds: -1 },
    { verified: true, authAgeSeconds: null },
    { verified: 'true', authAgeSeconds: 60 },
    { verified: false, authAgeSeconds: null },
    undefined, null, 'verified',
  ]) {
    assert.equal((await decide(fresh(suspicious, { stepUp }))).decision, 'step_up');
  }
});

test('지역만 다르면 허용이다', async () => {
  const { normal } = fixtureRequests();
  const result = await decide(withSignals(normal, { region: 'foreign' }));
  assert.equal(result.decision, 'allow');
  assert.equal(explainStepUp(withSignals(normal, { region: 'foreign' })).matched, false);
});

test('시각만, 네트워크만, 행동만 이상하면 허용이다', async () => {
  const { normal } = fixtureRequests();
  for (const request of [
    withSignals(normal, { hour: 3 }),
    withSignals(normal, { network: 'unusual' }),
    fresh(normal, { recentEvents: burst(20) }),
    withSignals(fresh(normal, { recentEvents: burst(20) }), { hour: 3 }),
    withSignals(withSignals(normal, { hour: 3 }), { network: 'unusual' }),
  ]) {
    assert.equal((await decide(request)).decision, 'allow');
  }
});

test('행동 기준: 9회와 오래된 사건은 포함하지 않고 10회는 포함한다', async () => {
  const { suspicious } = fixtureRequests();
  assert.equal((await decide(fresh(suspicious, { recentEvents: burst(9) }))).decision, 'allow');
  assert.equal((await decide(fresh(suspicious, { recentEvents: burst(10) }))).decision, 'step_up');
  assert.equal((await decide(fresh(suspicious, { recentEvents: [{ kind: 'risk_signal', ageSeconds: 301, count: 50 }] }))).decision, 'allow');
  assert.equal((await decide(fresh(suspicious, { recentEvents: [{ kind: 'other', ageSeconds: 1, count: 50 }] }))).decision, 'allow');
  assert.equal((await decide(fresh(suspicious, { recentEvents: [burst(5)[0], burst(5)[0]] }))).decision, 'step_up');
});

test('시각 경계: 5시는 새벽이고 6시는 아니다', async () => {
  const { suspicious } = fixtureRequests();
  assert.equal((await decide(withSignals(suspicious, { hour: 5 }))).decision, 'step_up');
  assert.equal((await decide(withSignals(suspicious, { hour: 6 }))).decision, 'allow');
});

test('출처가 none이거나 값이 없거나 틀리면 규칙이 작동하지 않는다', async () => {
  const { suspicious } = fixtureRequests();
  for (const request of [
    withSignals(suspicious, { source: 'none' }),
    fresh(suspicious, { signals: undefined }),
    fresh(suspicious, { recentEvents: undefined }),
    withSignals(suspicious, { hour: 99 }),
    fresh(suspicious, { headers: { 'x-forwarded-for': '1.2.3.4' }, signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 3 } }),
  ]) {
    assert.equal((await decide(request)).decision, 'allow');
  }
});

test('미등록 기기는 복합 이상 여부와 상관없이 거부한다', async () => {
  const { normal, suspicious } = fixtureRequests();
  for (const request of [normal, suspicious]) {
    const result = await decide(fresh(request, { deviceRegistered: false }));
    assert.equal(result.decision, 'deny');
    assert.equal(result.reasonCode, 'device_not_registered');
    assert.deepEqual(result.ruleIds, ['device_registered']);
  }
  const verified = await decide(fresh(suspicious, { deviceRegistered: false, stepUp: { verified: true, authAgeSeconds: 1 } }));
  assert.equal(verified.decision, 'deny');
  assert.equal((await decide(fresh(suspicious, { deviceRegistered: 'true' }))).decision, 'deny');
});

test('지역만으로는 거부하지 않는다', async () => {
  const { normal } = fixtureRequests();
  for (const region of ['foreign', 'unknown', 'other']) {
    assert.notEqual((await decide(withSignals(normal, { region }))).decision, 'deny');
  }
});
