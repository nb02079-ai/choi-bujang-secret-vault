// 무차별 로그인 공격 경보를 block / alert / record로 나눕니다. 경보 원본은 고치지 않고 네트워크도 쓰지 않습니다.
// 같은 경보에는 항상 같은 답을 냅니다(저장된 상태 없음). 판정기 규칙을 대신하지 않고, 확인 단계 하나로 불러 쓰는 부품입니다.
//
// 기준 (경계값 포함, 정확히 그 값이면 해당 행동):
//   block  실패 15건 이상 또는 서로 다른 계정 5개 이상 — 그리고 성공 언급이 없고 srcip가 올바른 주소일 때만
//   alert  실패 3건 이상 또는 서로 다른 계정 2개 이상, 또는 위 block 조건이지만 성공이 섞였거나 주소가 올바르지 않을 때
//   record 그 밖의 정상 이벤트, 그리고 형식을 읽을 수 없는 경보
export const BLOCK_FAILURES = 15;
export const BLOCK_ACCOUNTS = 5;
export const ALERT_FAILURES = 3;
export const ALERT_ACCOUNTS = 2;

const MAX_FAILURES = 1_000_000;
const MAX_ACCOUNTS = 100;
const ACCOUNT = /^[A-Za-z0-9._-]{1,64}$/u;
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/u;
const IPV6 = /^[0-9a-f:]{2,39}$/iu;
// "성공은 없습니다"는 성공이 아니므로, 성공했다는 말(성공했/성공하였)만 봅니다.
const SUCCESS = /성공(?:했|하였)/u;

const isAddress = (value) => typeof value === 'string'
  && (IPV4.test(value) || (value.includes(':') && IPV6.test(value) && value.split(':').length <= 8));

function failureCount(value) {
  if (value === undefined || value === null || value === '') return 0;
  const number = typeof value === 'number' ? value : (typeof value === 'string' && /^\d{1,7}$/u.test(value.trim()) ? Number(value) : NaN);
  return Number.isInteger(number) && number >= 0 && number <= MAX_FAILURES ? number : null;
}

function accountCount(value) {
  if (value === undefined || value === null || value === '') return 0;
  if (typeof value !== 'string') return null;
  const names = value.split(',').map((name) => name.trim());
  if (names.length > MAX_ACCOUNTS || names.some((name) => !ACCOUNT.test(name))) return null;
  return new Set(names).size;
}

const answer = (action, confidence, reason) => ({ action, confidence, reason });

export function assess(alert) {
  const data = alert?.data;
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return answer('record', 0.5, '경보 형식을 읽을 수 없어 기록만 합니다.');
  }
  const failures = failureCount(data.count);
  const accounts = accountCount(data.accounts);
  if (failures === null || accounts === null) {
    return answer('record', 0.5, '실패 건수나 계정 목록을 읽을 수 없어 기록만 합니다.');
  }
  const succeeded = typeof alert.rule?.description === 'string' && SUCCESS.test(alert.rule.description);

  if (failures >= BLOCK_FAILURES || accounts >= BLOCK_ACCOUNTS) {
    if (succeeded) return answer('alert', 0.9, '실패가 기준을 넘었고 성공이 섞여 있어 사람이 확인해야 합니다.');
    if (!isAddress(data.srcip)) return answer('alert', 0.8, '실패가 기준을 넘었지만 막을 주소가 올바르지 않아 사람이 확인해야 합니다.');
    const strong = failures >= BLOCK_FAILURES * 2 || accounts >= BLOCK_ACCOUNTS * 2;
    return answer('block', strong ? 0.95 : 0.85, '같은 주소의 로그인 실패가 기준을 크게 넘었고 성공이 없어 막습니다.');
  }
  if (failures >= ALERT_FAILURES || accounts >= ALERT_ACCOUNTS) {
    return answer('alert', 0.6, '로그인 실패가 있지만 막을 만큼 명확하지 않아 알립니다.');
  }
  return answer('record', 0.9, '반복 실패 신호가 없어 기록만 합니다.');
}

export async function decide(alert) {
  return assess(alert);
}
