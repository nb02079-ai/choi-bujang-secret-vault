import test from 'node:test';
import assert from 'node:assert/strict';
import { detect, readDetectionEvents } from '../src/detect.mjs';
import { checkDetection } from '../scripts/detect-test.mjs';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const OBSERVE = { action: 'observe' };
const DEVICE = 'a'.repeat(16);
const revoke = (subject, device = DEVICE) => ({ action: 'propose_revocation', reasonCode: 'burst_read', subject, device });
const reads = (count, { interval = 2, owner = 'learner_fixture', device = DEVICE, start = START, network, region, source = 'judge_fixture' } = {}) =>
  Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * interval * 1000).toISOString(), method: 'GET', identity: { sub: owner }, deviceId: device,
    ...(network || region ? { signals: { source, network: network ?? 'usual', region: region ?? 'local', hour: 14 } } : {}),
  }));
const unusualAt = (events, index) => events.map((event, i) => (i === index
  ? { ...event, signals: { source: 'judge_fixture', network: 'unusual', region: 'local', hour: 14 } } : event));

test('복합 의심: 10분 안에 121건과 평소와 다른 네트워크가 함께면 회수를 제안한다', () => {
  assert.deepEqual(detect(reads(121, { network: 'unusual' })), revoke('learner_fixture'));
  assert.deepEqual(detect(reads(200, { network: 'unusual' })), revoke('learner_fixture'));
  assert.deepEqual(detect(unusualAt(reads(121, { network: 'usual' }), 60)), revoke('learner_fixture'));
});

test('다량 조회만 있거나 네트워크만 이상하면 observe이다', () => {
  assert.deepEqual(detect(reads(121, { network: 'usual' })), OBSERVE);
  assert.deepEqual(detect(reads(200)), OBSERVE);
  assert.deepEqual(detect(reads(30, { network: 'unusual' })), OBSERVE);
  assert.deepEqual(detect(reads(120, { network: 'unusual' })), OBSERVE);
});

test('지역만 달라도 확정하지 않고 observe이다', () => {
  assert.deepEqual(detect(reads(200, { region: 'foreign' })), OBSERVE);
  assert.deepEqual(detect(reads(30, { region: 'foreign', network: 'usual' })), OBSERVE);
  assert.deepEqual(detect(reads(121, { region: 'foreign', network: 'usual' })), OBSERVE);
});

test('정상 사건은 그대로 observe이다', () => {
  assert.deepEqual(detect([]), OBSERVE);
  assert.deepEqual(detect(reads(30)), OBSERVE);
  assert.deepEqual(detect(reads(30, { network: 'usual' })), OBSERVE);
});

test('경계: 120건은 observe, 121건은 제안. 10분 구간은 시작 포함·끝 제외', () => {
  assert.deepEqual(detect(reads(120, { network: 'unusual', interval: 1 })), OBSERVE);
  assert.deepEqual(detect(reads(121, { network: 'unusual', interval: 1 })), revoke('learner_fixture'));
  // 첫 사건과 121번째 사건 사이가 정확히 600초이면 같은 구간이 아니다.
  const spread = reads(121, { network: 'unusual', interval: 5 });
  assert.equal(Date.parse(spread[120].at) - Date.parse(spread[0].at), 600000);
  assert.deepEqual(detect(spread), OBSERVE);
  assert.deepEqual(detect(reads(121, { network: 'unusual', interval: 4.99 })), revoke('learner_fixture'));
});

test('10분 밖으로 흩어진 조회와 다른 사용자의 사건은 합산하지 않는다', () => {
  assert.deepEqual(detect(reads(200, { network: 'unusual', interval: 7 })), OBSERVE);
  const mixed = [...reads(100, { network: 'unusual' }), ...reads(100, { network: 'unusual', owner: 'other_fixture' })]
    .sort((a, b) => a.at.localeCompare(b.at));
  assert.deepEqual(detect(mixed), OBSERVE);
  const withOther = [...reads(121, { network: 'usual' }), ...reads(5, { network: 'unusual', owner: 'other_fixture' })];
  assert.deepEqual(detect(withOther), OBSERVE);
});

test('제안은 다량 조회를 한 주체에게만 붙고 정상 주체는 유지된다', () => {
  const events = [...reads(30, { owner: 'normal_fixture', network: 'usual' }), ...reads(150, { owner: 'bad_fixture', network: 'unusual' })]
    .sort((a, b) => a.at.localeCompare(b.at));
  assert.deepEqual(detect(events), revoke('bad_fixture'));
  assert.deepEqual(detect(events.filter(event => event.identity.sub === 'normal_fixture')), OBSERVE);
});

test('출처가 judge_fixture가 아니거나 값이 틀리면 네트워크를 알 수 없음으로 두어 observe이다', () => {
  assert.deepEqual(detect(reads(200, { network: 'unusual', source: 'none' })), OBSERVE);
  assert.deepEqual(detect(reads(200, { network: 'unusual', source: 'browser' })), OBSERVE);
  const forged = reads(200).map(event => ({ ...event, network: 'unusual', headers: { 'x-network': 'unusual' },
    geo: { region: 'foreign' }, region: 'foreign', signals: { source: 'judge_fixture', network: 'weird' } }));
  assert.deepEqual(detect(forged), OBSERVE);
  assert.equal(readDetectionEvents(forged).events[0].network, null);
});

test('GET이 아니거나 주체·시각을 알 수 없는 사건은 세지 않는다', () => {
  const base = reads(121, { network: 'unusual' });
  assert.deepEqual(detect(base.map(event => ({ ...event, method: 'POST' }))), OBSERVE);
  assert.deepEqual(detect(base.map(event => ({ ...event, identity: {} }))), OBSERVE);
  assert.deepEqual(detect(base.map(event => ({ ...event, at: 'x' }))), OBSERVE);
  assert.deepEqual(detect([...base.slice(0, 120), null, 7, 'GET']), OBSERVE);
});

test('입력 순서가 뒤섞여도 같은 결과이고, 배열이 아니면 오류이다', () => {
  const events = reads(150, { network: 'unusual' });
  assert.deepEqual(detect([...events].reverse()), revoke('learner_fixture'));
  assert.throws(() => detect('x'), { name: 'TypeError', message: 'invalid_detection_events' });
});

test('출력에는 주체·기기·사유 코드만 있고 비밀 값은 없다', () => {
  const secret = ['sb', 'secret', 'e'.repeat(12)].join('_');
  const result = detect(reads(150, { network: 'unusual' }).map(event => ({ ...event, token: secret, body: '메모 내용 시험' })));
  assert.deepEqual(Object.keys(result).sort(), ['action', 'device', 'reasonCode', 'subject']);
  assert.ok(!JSON.stringify(result).includes(secret));
});

test('연습 계약 runner: 네트워크 값이 없는 연습 사건 2건은 엄격 방식에서 확인 필요로 남는다', async () => {
  const results = await checkDetection(async events => detect(events));
  const failed = results.filter(item => !item.passed).map(item => item.name).sort();
  assert.deepEqual(failed, ['10분 안에 121건', '폭주 조회 200건']);
});

const OTHER = 'b'.repeat(16);
const byTime = events => events.sort((a, b) => a.at.localeCompare(b.at));

test('같은 계정의 의심 기기 한 개만 제안하고 정상 기기는 유지된다', () => {
  const events = byTime([...reads(40, { device: OTHER, network: 'usual' }), ...reads(150, { device: DEVICE, network: 'unusual' })]);
  assert.deepEqual(detect(events), revoke('learner_fixture', DEVICE));
  assert.deepEqual(detect(events.filter(event => event.deviceId === OTHER)), OBSERVE);
});

test('조회량이 두 기기로 나뉘면 합산하지 않아 observe이다', () => {
  const events = byTime([...reads(70, { device: DEVICE, network: 'unusual' }), ...reads(70, { device: OTHER, network: 'unusual' })]);
  assert.deepEqual(detect(events), OBSERVE);
});

test('평소와 다른 네트워크는 다량 조회를 한 같은 기기의 사건에서만 센다', () => {
  const events = byTime([...reads(150, { device: DEVICE, network: 'usual' }), ...reads(3, { device: OTHER, network: 'unusual' })]);
  assert.deepEqual(detect(events), OBSERVE);
});

test('확인된 기기가 없거나 형식이 틀리면 대상을 추측하지 않고 observe이다', () => {
  const base = reads(150, { network: 'unusual' });
  for (const deviceId of [undefined, null, '', 'abc', 'A'.repeat(16), 'g'.repeat(16), 'a'.repeat(17), 7, ['a'.repeat(16)]]) {
    assert.deepEqual(detect(base.map(event => ({ ...event, deviceId }))), OBSERVE, String(deviceId));
  }
});

test('제안은 반환값뿐이다: 입력을 바꾸지 않고, 파일·네트워크·콘솔을 쓰지 않는다', async () => {
  const events = reads(150, { network: 'unusual' });
  const before = JSON.stringify(events);
  const originals = ['log', 'warn', 'error', 'info', 'debug'].map(name => [name, console[name]]);
  const realFetch = globalThis.fetch;
  let calls = 0;
  for (const [name] of originals) console[name] = () => { calls += 1; };
  globalThis.fetch = () => { calls += 1; throw new Error('network_not_allowed'); };
  let result;
  try { result = detect(events); } finally {
    for (const [name, original] of originals) console[name] = original;
    globalThis.fetch = realFetch;
  }
  assert.deepEqual(result, revoke('learner_fixture', DEVICE));
  assert.equal(calls, 0);
  assert.equal(JSON.stringify(events), before);
  const source = (await import('node:fs')).readFileSync(new URL('../src/detect.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /\b(fetch|writeFile|appendFile|require|child_process|XMLHttpRequest)\b|^\s*import\s/mu);
});
