import test from 'node:test';
import assert from 'node:assert/strict';
import { readSignals, decide } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const UNKNOWN = { region: null, network: null, hour: null };

test('엔진이 정한 출처의 정상 신호는 그대로 읽는다', () => {
  const { normal } = fixtureRequests();
  assert.deepEqual(readSignals(normal), {
    trusted: true, region: 'local', network: 'usual', hour: 14, events: [],
  });
});

test('source가 none이면 모든 값이 알 수 없음이다', () => {
  const { normal } = fixtureRequests();
  const read = readSignals({ ...normal, signals: { source: 'none', region: 'local', network: 'usual', hour: 14 } });
  assert.equal(read.trusted, false);
  assert.deepEqual({ region: read.region, network: read.network, hour: read.hour }, UNKNOWN);
});

test('알 수 없는 출처, signals 없음, 객체가 아닌 요청도 알 수 없음이다', () => {
  const { normal } = fixtureRequests();
  for (const request of [
    { ...normal, signals: { source: 'client_header', region: 'local', network: 'usual', hour: 14 } },
    { ...normal, signals: undefined },
    { ...normal, signals: 'judge_fixture' },
    null,
    undefined,
    'text',
  ]) {
    const read = readSignals(request);
    assert.equal(read.trusted, false);
    assert.deepEqual({ region: read.region, network: read.network, hour: read.hour }, UNKNOWN);
  }
});

test('위조한 헤더·위치 항목은 읽지 않는다', () => {
  const { normal } = fixtureRequests();
  const forged = {
    ...normal,
    signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 0 },
    headers: { 'x-forwarded-for': '1.2.3.4', 'x-region': 'local' },
    geo: { region: 'local' },
    region: 'local',
  };
  const read = readSignals(forged);
  assert.equal(read.trusted, false);
  assert.deepEqual({ region: read.region, network: read.network, hour: read.hour }, UNKNOWN);
  assert.equal(JSON.stringify(read).includes('1.2.3.4'), false);
});

test('상속된 값은 신뢰하지 않는다', () => {
  const { normal } = fixtureRequests();
  const inherited = Object.create({ source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 });
  const read = readSignals({ ...normal, signals: inherited });
  assert.equal(read.trusted, false);
  assert.deepEqual({ region: read.region, network: read.network, hour: read.hour }, UNKNOWN);
});

test('형식이 틀린 항목만 알 수 없음으로 둔다', () => {
  const { normal } = fixtureRequests();
  const read = readSignals({ ...normal, signals: { source: 'judge_fixture', region: 3, network: 'usual', hour: 99 } });
  assert.equal(read.trusted, true);
  assert.equal(read.region, null);
  assert.equal(read.network, 'usual');
  assert.equal(read.hour, null);
  for (const hour of [-1, 24, 1.5, '3', NaN]) {
    assert.equal(readSignals({ ...normal, signals: { ...normal.signals, hour } }).hour, null);
  }
});

test('recentEvents: 빈 배열은 사건 없음, 형식 오류는 알 수 없음이다', () => {
  const { normal, suspicious } = fixtureRequests();
  assert.deepEqual(readSignals(normal).events, []);
  assert.deepEqual(readSignals(suspicious).events, [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }]);
  const good = { kind: 'risk_signal', ageSeconds: 1, count: 1 };
  assert.equal(readSignals({ ...normal, recentEvents: Array(13).fill(good) }).events, null);
  assert.equal(readSignals({ ...normal, recentEvents: Array(12).fill(good) }).events.length, 12);
  for (const bad of [
    undefined, null, 'x', {},
    [{ kind: 3, ageSeconds: 1, count: 1 }],
    [{ kind: 'risk_signal', ageSeconds: -1, count: 1 }],
    [{ kind: 'risk_signal', ageSeconds: 1, count: 0 }],
    [{ kind: 'risk_signal', ageSeconds: 1.5, count: 1 }],
    [null],
  ]) {
    assert.equal(readSignals({ ...normal, recentEvents: bad }).events, null);
  }
});

test('입력 검사를 더해도 6단계 기기 판정은 그대로다', async () => {
  const { normal } = fixtureRequests();
  assert.equal((await decide(normal)).decision, 'allow');
  assert.equal((await decide({ ...normal, deviceRegistered: false })).reasonCode, 'device_not_registered');
});
