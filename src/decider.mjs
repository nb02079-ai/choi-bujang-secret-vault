// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 지금은 기기, 추가 확인, 구역 규칙(zone_*)을 구현했습니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'zone_route_exact', 'zone_notice_read_only', 'zone_instructor_denied']);

// 7-1단계 입력 검사: 엔진이 넘긴 signals·recentEvents만 읽고, 없거나 출처가 불명확하면 null(알 수 없음)로 둡니다.
// 정상값(local, usual 등)으로 채우지 않습니다. headers, geo 같은 계약 밖 이름은 읽지 않습니다.
const TRUSTED_SOURCES = Object.freeze(['judge_fixture']);
const MAX_EVENTS = 12;
const own = (object, key) => object !== null && typeof object === 'object'
  && Object.prototype.hasOwnProperty.call(object, key) ? object[key] : undefined;
const text = value => (typeof value === 'string' && value.length > 0 && value.length <= 64 ? value : null);

function readEvents(value) {
  if (!Array.isArray(value) || value.length > MAX_EVENTS) return null;
  const events = [];
  for (const item of value) {
    const kind = text(own(item, 'kind'));
    const ageSeconds = own(item, 'ageSeconds');
    const count = own(item, 'count');
    if (kind === null || !Number.isInteger(ageSeconds) || ageSeconds < 0
        || !Number.isInteger(count) || count < 1) return null;
    events.push({ kind, ageSeconds, count });
  }
  return events;
}

export function readSignals(request) {
  const signals = own(request, 'signals');
  const trusted = TRUSTED_SOURCES.includes(own(signals, 'source'));
  const hour = own(signals, 'hour');
  return {
    trusted,
    region: trusted ? text(own(signals, 'region')) : null,
    network: trusted ? text(own(signals, 'network')) : null,
    hour: trusted && Number.isInteger(hour) && hour >= 0 && hour <= 23 ? hour : null,
    events: readEvents(own(request, 'recentEvents')),
  };
}

// 7-2단계 step_up_required: 새벽 시각, 처음 보는 네트워크, 짧은 시간의 많은 읽기가 모두 참일 때만 추가 확인을 요구합니다.
// 값이 null(알 수 없음)이면 그 조건은 거짓입니다. 지역은 사유에만 보조로 남기며 단독 근거로 쓰지 않습니다.
const ODD_HOUR_MAX = 5;
const BURST_WINDOW_SECONDS = 300;
const BURST_COUNT_MIN = 10;
const STEP_UP_MAX_AGE_SECONDS = 900;

// 맞은 조건 이름만 돌려줍니다. 주소, 계정 같은 실제 값은 담지 않습니다.
export function explainStepUp(request) {
  const { trusted, region, network, hour, events } = readSignals(request);
  const reasons = [];
  if (hour !== null && hour <= ODD_HOUR_MAX) reasons.push('odd_hour');
  if (network === 'unusual') reasons.push('unseen_network');
  if (events !== null && events
    .filter(item => item.kind === 'risk_signal' && item.ageSeconds <= BURST_WINDOW_SECONDS)
    .reduce((sum, item) => sum + item.count, 0) >= BURST_COUNT_MIN) reasons.push('burst_read');
  const matched = ['odd_hour', 'unseen_network', 'burst_read'].every(name => reasons.includes(name));
  if (trusted && matched && region !== null && region !== 'local') reasons.push('region_unusual');
  return { matched, reasons };
}

const reverified = stepUp => stepUp !== null && typeof stepUp === 'object' && stepUp.verified === true
  && Number.isInteger(stepUp.authAgeSeconds) && stepUp.authAgeSeconds >= 0
  && stepUp.authAgeSeconds <= STEP_UP_MAX_AGE_SECONDS;

// 8단계 구역 규칙: 서비스와 route·path의 정확한 모양으로 메모·반 공지·강사 자료를 나눕니다.
// 역할은 요청에 없으므로 쓰지 않습니다. 강사의 공지 수정은 판정기가 아니라 서버의 관리 경로에서 처리합니다.
// 메모 주인 비교는 판정기에서 하지 않고 자료 API(src/notes-api.mjs)에서 합니다.
// 새 이유 코드는 운영 등록부에 있는지 확인하지 못했습니다. 바꿀 때는 이 상수만 고칩니다.
export const ZONE_REASON_CODES = Object.freeze({ route: 'route_not_allowed', zone: 'zone_forbidden' });
const ZONE_ROUTES = Object.freeze({
  notes: Object.freeze(['GET /notes/:id', 'PUT /notes/:id', 'DELETE /notes/:id', 'POST /notes/:id/restore']),
  notices: Object.freeze(['GET /notices', 'GET /notices/:id']),
});
const WRITE_METHODS = Object.freeze(['POST', 'PUT', 'PATCH', 'DELETE']);
// :id와 같은 깊이에서 기능을 고르는 이름은 자료 ID로 받지 않습니다. ID 형식(UUID 여부)은 좁히지 않습니다.
const FUNCTION_NAMES = Object.freeze([
  'export', 'import', 'search', 'list', 'all', 'new', 'bulk',
  'me', 'mine', 'my', 'own', 'public', 'shared', 'share', 'everyone', 'users', 'user',
  'recent', 'latest', 'count', 'stats', 'summary', 'index', 'root',
  'admin', 'download', 'upload', 'backup', 'dump', 'sync', 'restore', 'batch',
]);
const safeId = value => typeof value === 'string' && value.length >= 1 && value.length <= 128
  && !/[/?#\\%\s\u0000-\u001f\u007f]/u.test(value) && value !== '.' && value !== '..'
  && !FUNCTION_NAMES.includes(value.toLowerCase());

// route 모양과 path가 정확히 같을 때만 true입니다. 쿼리는 읽지 않습니다.
function exactRoute(service, method, route, path) {
  if (!Object.hasOwn(ZONE_ROUTES, service) || !ZONE_ROUTES[service].includes(route) || !route.startsWith(`${method} `)) return false;
  const want = route.slice(method.length + 1).split('/');
  const have = path.split('/');
  return want.length === have.length
    && want.every((part, index) => (part === ':id' ? safeId(have[index]) : part === have[index]));
}

// 구역에서 거부할 때만 { reasonCode, ruleId }를 돌려주고, 통과하면 null을 돌려줍니다.
export function checkZone(request) {
  const text = value => (typeof value === 'string' ? value : '');
  const service = text(request?.service);
  const method = text(request?.method);
  const route = text(request?.route);
  const path = text(request?.path);
  const first = path.split('/')[1] ?? '';
  if (service === 'instructor' || first === 'instructor') {
    return { reasonCode: ZONE_REASON_CODES.zone, ruleId: RULE_IDS[4] };
  }
  if ((service === 'notices' || first === 'notices') && WRITE_METHODS.includes(method)) {
    return { reasonCode: ZONE_REASON_CODES.zone, ruleId: RULE_IDS[3] };
  }
  return exactRoute(service, method, route, path) ? null
    : { reasonCode: ZONE_REASON_CODES.route, ruleId: RULE_IDS[2] };
}

export async function decide(request) {
  // 6단계 device_registered: 엔진이 확인한 deviceRegistered가 true일 때만 허용합니다.
  // false, 값 없음, 그 밖의 값은 모두 미등록으로 보고 거부합니다.
  const registered = request?.deviceRegistered === true;
  const verdict = (decision, reasonCode, ruleId) => ({
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision,
    reasonCode,
    ruleIds: [ruleId],
  });
  if (!registered) return verdict('deny', 'device_not_registered', RULE_IDS[0]);
  const zone = checkZone(request);
  if (zone) return verdict('deny', zone.reasonCode, zone.ruleId);
  if (explainStepUp(request).matched) {
    return reverified(request.stepUp)
      ? verdict('allow', 'approved', RULE_IDS[1])
      : verdict('step_up', 'step_up_required', RULE_IDS[1]);
  }
  return verdict('allow', 'approved', RULE_IDS[0]);
}

// 10단계: 현재 정책의 읽기 전용 복사본입니다. 정책 사본과 비교할 때만 쓰며, 이 값을 바꿔도 판정에는 영향이 없습니다.
export function describePolicy() {
  const lists = map => Object.fromEntries(Object.entries(map).map(([name, list]) => [name, [...list]]));
  return {
    ruleIds: [...RULE_IDS],
    reasonCodes: { ...ZONE_REASON_CODES, deviceNotRegistered: 'device_not_registered', approved: 'approved', stepUpRequired: 'step_up_required' },
    zoneRoutes: lists(ZONE_ROUTES),
    writeMethods: [...WRITE_METHODS],
    functionNames: [...FUNCTION_NAMES],
    stepUp: { oddHourMax: ODD_HOUR_MAX, burstWindowSeconds: BURST_WINDOW_SECONDS, burstCountMin: BURST_COUNT_MIN, maxAgeSeconds: STEP_UP_MAX_AGE_SECONDS },
    trustedSources: [...TRUSTED_SOURCES],
  };
}
