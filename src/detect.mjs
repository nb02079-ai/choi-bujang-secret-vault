// 9단계에서 학생이 채우는 탐지 함수입니다. 이 기본값은 어떤 접속도 회수하지 않습니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.
const METHODS = Object.freeze(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const DECISIONS = Object.freeze(['allow', 'deny', 'step_up']);
const present = value => value !== undefined && value !== null;
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const pseudonym = value => typeof value === 'string' && value.length >= 1 && value.length <= 128
  && !/[\s\u0000-\u001f\u007f]/u.test(value);

// 가명 주체는 identity.sub(연습 사건)나 subjectId(판정기 요청)에서만 읽고, 둘 다 있으면 같아야 합니다.
function readSubject(event) {
  const found = [isObject(event.identity) ? event.identity.sub : undefined, event.subjectId].filter(present);
  if (found.length === 0 || !found.every(pseudonym) || found.some(value => value !== found[0])) return null;
  return found[0];
}

// 네트워크는 엔진이 넘긴 가상 사건(signals.source가 judge_fixture)일 때만 읽습니다. 지역은 읽지 않습니다.
function readNetwork(event) {
  const signals = event.signals;
  if (!isObject(signals) || signals.source !== 'judge_fixture') return null;
  return signals.network === 'usual' || signals.network === 'unusual' ? signals.network : null;
}

function readTime(value) {
  if (typeof value !== 'string' || value.length > 40) return null;
  const at = Date.parse(value);
  return Number.isFinite(at) ? at : null;
}

// 사건마다 가명 주체·기기·요청 종류·판정·시각만 새 객체에 옮깁니다. 값이 없거나 형식이 틀리면 null이고
// 임의의 정상값으로 채우지 않습니다. 메모 내용, 토큰, 헤더, 이름처럼 그 밖의 값은 읽지도 복사하지도 않습니다.
// 객체가 아닌 항목은 건너뛰고 건수만 skipped로 셉니다.
export function readDetectionEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  const read = [];
  let skipped = 0;
  for (const event of events) {
    if (!isObject(event)) { skipped += 1; continue; }
    read.push(Object.freeze({
      subject: readSubject(event),
      device: typeof event.deviceId === 'string' && /^[0-9a-f]{16}$/u.test(event.deviceId) ? event.deviceId : null,
      kind: METHODS.includes(event.method) ? event.method : null,
      decision: DECISIONS.includes(event.decision) ? event.decision : null,
      network: readNetwork(event),
      at: readTime(event.at),
    }));
  }
  return Object.freeze({ events: Object.freeze(read), skipped });
}

// 탐지 규칙 하나(burst_read): 같은 (주체, 기기) 쌍의 GET이 10분 구간(시작 포함, 끝 제외)에서 120건을 넘고
// 그 구간의 사건에 평소와 다른 네트워크가 함께 있을 때만 확인된 기기 한 개의 회수를 제안합니다.
// 다량 조회만, 네트워크만, 지역만으로는 제안하지 않습니다. 다른 주체나 같은 계정의 다른 기기 사건은 합산하지 않으므로
// 정상 기기는 유지됩니다. 확인된 기기(16자리 deviceId)가 없는 사건은 세지 않아 대상을 추측하지 않습니다.
// 이 함수는 제안만 반환합니다. 회수 실행, 회수 API 호출, 기기 권한 변경, 기록 쓰기는 하지 않으며
// 실제 회수와 걸린 시간은 심판이 확인합니다. 기준(120건, 10분)은 docs/DETECT_EVENTS.md의 연습 계약을 따릅니다.
const BURST_WINDOW_MS = 10 * 60 * 1000;
const BURST_READ_MAX = 120;

function burstWithUnusualNetwork(times) {
  // times: 한 (주체, 기기) 쌍의 GET 사건을 시각 순으로 정렬한 [{ at, unusual }]
  let start = 0;
  let unusual = 0;
  for (let end = 0; end < times.length; end += 1) {
    if (times[end].unusual) unusual += 1;
    while (times[end].at - times[start].at >= BURST_WINDOW_MS) {
      if (times[start].unusual) unusual -= 1;
      start += 1;
    }
    if (end - start + 1 > BURST_READ_MAX && unusual > 0) return true;
  }
  return false;
}

export function detect(events) {
  const { events: read } = readDetectionEvents(events);
  const byDevice = new Map();
  for (const event of read) {
    if (event.subject === null || event.device === null || event.kind !== 'GET' || event.at === null) continue;
    const key = JSON.stringify([event.subject, event.device]);
    if (!byDevice.has(key)) byDevice.set(key, { subject: event.subject, device: event.device, times: [] });
    byDevice.get(key).times.push({ at: event.at, unusual: event.network === 'unusual' });
  }
  for (const { subject, device, times } of byDevice.values()) {
    if (burstWithUnusualNetwork(times.sort((a, b) => a.at - b.at))) {
      return { action: 'propose_revocation', reasonCode: 'burst_read', subject, device };
    }
  }
  return { action: 'observe' };
}
