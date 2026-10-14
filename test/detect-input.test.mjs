import test from 'node:test';
import assert from 'node:assert/strict';
import { detect, readDetectionEvents } from '../src/detect.mjs';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const reads = (count, owner = 'learner_fixture') => Array.from({ length: count }, (_, index) => ({
  at: new Date(START + index * 2000).toISOString(), method: 'GET', identity: { sub: owner },
}));
// 키 모양 가짜 값은 실행할 때 조립해 저장소 파일에 남지 않게 합니다.
const fake = {
  token: ['eyJ', 'a'.repeat(14), '.eyJ', 'b'.repeat(14), '.', 'c'.repeat(10)].join(''),
  secret: ['sb', 'secret', 'd'.repeat(12)].join('_'),
  body: '비공개 메모 내용 시험',
  name: '홍길동 시험',
};
const noisy = event => ({ ...event, authorization: `Bearer ${fake.token}`, token: fake.token, apikey: fake.secret,
  body: fake.body, content: fake.body, title: fake.body, name: fake.name, realName: fake.name,
  headers: { 'x-user-id': 'admin', cookie: fake.secret }, query: `q=${fake.body}`,
  identity: { ...event.identity, email: 'a@example.test', name: fake.name } });
const KEYS = 'at,decision,device,kind,network,subject';

test('정상 사건 30건을 가명 주체와 요청 종류로 읽는다', () => {
  const { events, skipped } = readDetectionEvents(reads(30));
  assert.equal(events.length, 30);
  assert.equal(skipped, 0);
  assert.deepEqual({ ...events[0] }, { subject: 'learner_fixture', device: null, kind: 'GET', decision: null, network: null, at: START });
  assert.equal(Object.keys(events[0]).sort().join(','), KEYS);
});

test('의심 사건 121건에 비밀 값이 섞여도 다섯 항목만 읽고 나머지는 버린다', () => {
  const { events } = readDetectionEvents(reads(121).map(event => noisy({ ...event, deviceId: 'a'.repeat(16), decision: 'allow' })));
  assert.equal(events.length, 121);
  for (const event of events) {
    assert.equal(Object.keys(event).sort().join(','), KEYS);
    assert.deepEqual({ ...event, at: 0 }, { subject: 'learner_fixture', device: 'a'.repeat(16), kind: 'GET', decision: 'allow', network: null, at: 0 });
  }
  const text = JSON.stringify(events);
  for (const value of [fake.token, fake.secret, fake.body, fake.name, 'admin', 'example.test', 'Bearer', 'cookie']) {
    assert.ok(!text.includes(value), value);
  }
});

test('읽는 동안 콘솔에 아무것도 출력하지 않는다', () => {
  const originals = ['log', 'warn', 'error', 'info', 'debug'].map(name => [name, console[name]]);
  let calls = 0;
  for (const [name] of originals) console[name] = () => { calls += 1; };
  try { readDetectionEvents(reads(5).map(noisy)); detect(reads(5).map(noisy)); } finally {
    for (const [name, original] of originals) console[name] = original;
  }
  assert.equal(calls, 0);
});

test('subjectId만 있는 판정기 요청 모양도 읽고, 두 값이 다르면 알 수 없음이다', () => {
  const { events } = readDetectionEvents([
    { at: new Date(START).toISOString(), method: 'GET', subjectId: 'pseudo_a' },
    { at: new Date(START).toISOString(), method: 'GET', subjectId: 'pseudo_a', identity: { sub: 'pseudo_a' } },
    { at: new Date(START).toISOString(), method: 'GET', subjectId: 'pseudo_a', identity: { sub: 'pseudo_b' } },
  ]);
  assert.deepEqual(events.map(event => event.subject), ['pseudo_a', 'pseudo_a', null]);
});

test('값이 없거나 형식이 틀리면 정상값으로 채우지 않고 null이다', () => {
  const bad = [
    {},
    { at: 'not-a-date', method: 'get', identity: { sub: ' ' }, deviceId: 'ABCDEF0123456789', decision: 'ALLOW' },
    { at: 12345, method: 'HEAD', identity: { sub: 'x'.repeat(129) }, deviceId: 'abc', decision: 'maybe' },
    { at: START, method: ['GET'], identity: 'learner_fixture', deviceId: 7, decision: 7, subjectId: 'a\nb' },
    { at: 'x'.repeat(41), method: 'Get', identity: { sub: 'a\u0000b' } },
  ];
  const { events, skipped } = readDetectionEvents(bad);
  assert.equal(skipped, 0);
  for (const event of events) {
    assert.deepEqual({ ...event }, { subject: null, device: null, kind: null, decision: null, network: null, at: null });
  }
});

test('객체가 아닌 항목은 건너뛰고 건수만 센다. 배열이 아니면 오류다', () => {
  const { events, skipped } = readDetectionEvents([null, 7, 'GET', [], undefined, reads(1)[0]]);
  assert.equal(events.length, 1);
  assert.equal(skipped, 5);
  for (const input of [undefined, null, {}, 'events', 7]) {
    assert.throws(() => readDetectionEvents(input), { name: 'TypeError', message: 'invalid_detection_events' });
  }
});

test('결과는 원본 사건을 가리키지 않고 얼려 있다', () => {
  const source = reads(2);
  const result = readDetectionEvents(source);
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.events) && Object.isFrozen(result.events[0]));
  source[0].identity.sub = 'changed';
  assert.equal(result.events[0].subject, 'learner_fixture');
});

test('네트워크 값이 없는 사건은 다량 조회여도 observe이다', () => {
  assert.deepEqual(detect(reads(200)), { action: 'observe' });
  assert.throws(() => detect('x'), TypeError);
});
