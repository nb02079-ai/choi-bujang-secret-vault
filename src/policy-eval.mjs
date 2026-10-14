// 10단계: 시험 정책 값으로 가상 요청을 판정해 보는 평가기입니다. src/decider.mjs의 decide()와 같은 규칙을
// 정책 값으로 다시 구현했으며, 기본 정책에서 decide()와 같은 결과인지 test/policy-eval.test.mjs가 대조합니다.
// 이 파일은 파일 쓰기와 네트워크 호출을 하지 않고, 심판이 판정하는 decide()에는 영향을 주지 않습니다.
import { readSignals } from './decider.mjs';

const own = (object, key) => object !== null && typeof object === 'object' && Object.hasOwn(object, key) ? object[key] : undefined;

function safeId(policy, value) {
  return typeof value === 'string' && value.length >= 1 && value.length <= 128
    && !/[/?#\\%\s\u0000-\u001f\u007f]/u.test(value) && value !== '.' && value !== '..'
    && !policy.functionNames.some(name => name.toLowerCase() === value.toLowerCase());
}

function exactRoute(policy, service, method, route, path) {
  if (!Object.hasOwn(policy.zoneRoutes, service) || !policy.zoneRoutes[service].includes(route) || !route.startsWith(`${method} `)) return false;
  const want = route.slice(method.length + 1).split('/');
  const have = path.split('/');
  return want.length === have.length
    && want.every((part, index) => (part === ':id' ? safeId(policy, have[index]) : part === have[index]));
}

// 구역에서 거부할 때만 { reasonCode, ruleId }를 돌려줍니다. 강사 자료 거부는 정책 값이 아니라 고정 규칙입니다.
export function zoneVerdict(policy, request) {
  const text = value => (typeof value === 'string' ? value : '');
  const service = text(request?.service);
  const method = text(request?.method);
  const route = text(request?.route);
  const path = text(request?.path);
  const first = path.split('/')[1] ?? '';
  if (service === 'instructor' || first === 'instructor') return { reasonCode: policy.reasonCodes.zone, ruleId: policy.ruleIds[4] };
  if ((service === 'notices' || first === 'notices') && policy.writeMethods.includes(method)) {
    return { reasonCode: policy.reasonCodes.zone, ruleId: policy.ruleIds[3] };
  }
  return exactRoute(policy, service, method, route, path) ? null : { reasonCode: policy.reasonCodes.route, ruleId: policy.ruleIds[2] };
}

function stepUpMatched(policy, request) {
  const signals = readSignals(request);
  const trusted = signals.trusted && policy.trustedSources.includes(own(own(request, 'signals'), 'source'));
  const { oddHourMax, burstWindowSeconds, burstCountMin } = policy.stepUp;
  const hour = trusted ? signals.hour : null;
  const network = trusted ? signals.network : null;
  const burst = signals.events !== null && signals.events
    .filter(item => item.kind === 'risk_signal' && item.ageSeconds <= burstWindowSeconds)
    .reduce((sum, item) => sum + item.count, 0) >= burstCountMin;
  return hour !== null && hour <= oddHourMax && network === 'unusual' && burst;
}

export function decideWithPolicy(policy, request) {
  if (!Array.isArray(policy?.ruleIds) || policy.ruleIds.length < 5) throw new TypeError('invalid_policy');
  const verdict = (decision, reasonCode, ruleId) => ({
    schema: 'aleph.decision.v1', requestId: request?.requestId, decision, reasonCode, ruleIds: [ruleId],
  });
  if (request?.deviceRegistered !== true) return verdict('deny', policy.reasonCodes.deviceNotRegistered, policy.ruleIds[0]);
  const zone = zoneVerdict(policy, request);
  if (zone) return verdict('deny', zone.reasonCode, zone.ruleId);
  if (stepUpMatched(policy, request)) {
    const stepUp = request.stepUp;
    const reverified = stepUp !== null && typeof stepUp === 'object' && stepUp.verified === true
      && Number.isInteger(stepUp.authAgeSeconds) && stepUp.authAgeSeconds >= 0 && stepUp.authAgeSeconds <= policy.stepUp.maxAgeSeconds;
    return reverified ? verdict('allow', policy.reasonCodes.approved, policy.ruleIds[1])
      : verdict('step_up', policy.reasonCodes.stepUpRequired, policy.ruleIds[1]);
  }
  return verdict('allow', policy.reasonCodes.approved, policy.ruleIds[0]);
}
