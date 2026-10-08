// 무차별 로그인 공격 경보를 block / alert / record로 나눕니다.
// 이 파일은 혼자 계산합니다: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않습니다.
// 경보 원본은 고치지 않습니다. 같은 경보에는 항상 같은 답을 냅니다(저장된 상태 없음).
// 판정기 규칙을 대신하지 않고, 확인 단계 하나로 불러 쓰는 부품입니다.

// 패턴 목록: xdr/brute-force/patterns.json 과 같은 내용입니다(시험이 두 곳이 같은지 비교합니다).
// 근거는 MITRE ATT&CK T1110 입니다. thresholds 의 숫자는 MITRE 값이 아니라 이 수업의 학생 기준입니다.
// PATTERNS-BEGIN
const PATTERNS = [
  {
    "name": "rapid_failures_same_source",
    "technique": "T1110.001",
    "condition": "같은 주소의 로그인 실패가 짧은 시간 안에 연속해 쌓여 경보의 data.count가 15건 이상이다.",
    "fields": ["data.srcip", "data.srcuser", "data.count"],
    "thresholds": { "failures": 15 },
    "evidence": "T1110.001(Password Guessing)은 반복적·순차적 방식으로 비밀번호를 추측하며, 감지 기준이 한 곳 이상의 원격 IP에서 같거나 비슷한 계정을 향한 인증 실패의 연속이다.",
    "source": "https://attack.mitre.org/techniques/T1110/001/"
  },
  {
    "name": "password_spraying_many_accounts",
    "technique": "T1110.003",
    "condition": "한 주소가 같은 비밀번호를 서로 다른 계정 여러 개에 넣어 경보의 data.accounts에 서로 다른 계정이 5개 이상 적혀 있다.",
    "fields": ["data.srcip", "data.accounts"],
    "thresholds": { "accounts": 5 },
    "evidence": "T1110.003(Password Spraying)은 흔한 비밀번호 하나 또는 소수를 많은 서로 다른 계정에 시도하는 기법이고, 감지 기준이 정해진 시간 창 안에서 여러 계정에 걸친 인증 실패다.",
    "source": "https://attack.mitre.org/techniques/T1110/003/"
  },
  {
    "name": "failures_then_success",
    "technique": "T1110",
    "condition": "로그인 실패가 쌓인 뒤 성공했다는 설명(rule.description)이 같은 경보에 있다. 이때는 막지 않고 사람이 확인하도록 알린다.",
    "fields": ["data.srcip", "data.srcuser", "data.count", "rule.description"],
    "thresholds": {},
    "evidence": "T1110의 감지 전략은 많은 실패 뒤에 같은 IP나 사용자에서 성공이 이어지는 경우를 의심스러운 신호로 든다.",
    "source": "https://attack.mitre.org/techniques/T1110/"
  }
];
// PATTERNS-END

const byName = (name) => PATTERNS.find((pattern) => pattern.name === name);
const RAPID = byName('rapid_failures_same_source');
const SPRAY = byName('password_spraying_many_accounts');
const THEN_SUCCESS = byName('failures_then_success');

// 확신도 = 경보가 패턴과 얼마나 뚜렷하게 맞는지(0~1). 행동은 확신도로만 정합니다.
const BLOCK_AT = 0.85; // 이 값 이상이면 block
const ALERT_AT = 0.5; // 이 값 이상이면 alert, 그 아래는 record
const WEAK_FAILURES = 3; // 이 건수부터 패턴과 약하게 맞기 시작함(0.5)
const WEAK_ACCOUNTS = 2; // 이 계정 수부터 패턴과 약하게 맞기 시작함(0.5)
const STRONG_CAP = 0.95; // 기준의 두 배 이상이면 가장 뚜렷함
const UNSAFE_CAP = 0.8; // 성공이 섞였거나 막을 주소가 올바르지 않으면 막지 않도록 이 값 아래로 제한

const MAX_FAILURES = 1_000_000;
const MAX_ACCOUNTS = 100;
const ACCOUNT = /^[A-Za-z0-9._-]{1,64}$/u;
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/u;
const IPV6 = /^[0-9a-f:]{2,39}$/iu;
// "성공은 없습니다"는 성공이 아니므로, 성공했다는 말(성공했/성공하였)만 봅니다.
const SUCCESS = /성공(?:했|하였)/u;

const isAddress = (value) => typeof value === 'string'
  && (IPV4.test(value) || (value.includes(':') && IPV6.test(value) && value.split(':').length <= 8));
const round2 = (number) => Math.round(number * 100) / 100;

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

// value가 weak 미만이면 0, weak 이상 limit 미만이면 0.5~0.85 미만, limit 이상이면 0.85부터 limit의 두 배에서 0.95.
function strength(value, weak, limit) {
  if (value < weak) return 0;
  if (value < limit) return round2(ALERT_AT + (BLOCK_AT - ALERT_AT - 0.01) * ((value - weak) / (limit - weak)));
  return round2(Math.min(STRONG_CAP, BLOCK_AT + (STRONG_CAP - BLOCK_AT) * ((value - limit) / limit)));
}

const result = (confidence, reason) => ({
  action: confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record',
  confidence,
  reason,
});

export function decide(alert) {
  const data = alert?.data;
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return result(0, '맞는 패턴 없음: 경보 형식을 읽을 수 없어 기록만 합니다.');
  }
  const failures = failureCount(data.count);
  const accounts = accountCount(data.accounts);
  if (failures === null || accounts === null) {
    return result(0, '맞는 패턴 없음: 실패 건수나 계정 목록을 읽을 수 없어 기록만 합니다.');
  }

  const matches = [
    { pattern: RAPID, score: strength(failures, WEAK_FAILURES, RAPID.thresholds.failures) },
    { pattern: SPRAY, score: strength(accounts, WEAK_ACCOUNTS, SPRAY.thresholds.accounts) },
  ].filter((match) => match.score > 0).sort((a, b) => b.score - a.score);
  if (!matches.length) return result(0, '맞는 패턴 없음: 반복 실패 신호가 없어 기록만 합니다.');

  let confidence = matches[0].score;
  const names = matches.map((match) => match.pattern.name);
  let note = '';
  const succeeded = typeof alert.rule?.description === 'string' && SUCCESS.test(alert.rule.description);
  if (succeeded) {
    names.push(THEN_SUCCESS.name);
    confidence = Math.min(confidence, UNSAFE_CAP);
    note = ' 성공이 섞여 있어 막지 않고 사람이 확인합니다.';
  } else if (confidence >= BLOCK_AT && !isAddress(data.srcip)) {
    confidence = Math.min(confidence, UNSAFE_CAP);
    note = ' 막을 주소가 올바르지 않아 막지 않고 사람이 확인합니다.';
  }
  return result(confidence, `${names.join(' + ')}:${note || (confidence >= BLOCK_AT ? ' 기준을 넘었고 성공이 없어 막습니다.' : ' 막을 만큼 명확하지 않아 알립니다.')}`);
}
