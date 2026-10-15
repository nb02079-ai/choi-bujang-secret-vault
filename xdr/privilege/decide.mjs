// 계정·그룹 변경 경보와 관리자 권한 사용 경보를 block / alert / record로 나눕니다.
// 이 파일은 혼자 계산합니다: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않습니다.
// 경보 원본은 고치지 않습니다. 같은 경보에는 항상 같은 답을 냅니다(저장된 상태 없음).
// 판정기 규칙을 대신하지 않고, 확인 단계 하나로 불러 쓰는 부품입니다.
//
// 막는 것은 평소와 다른 권한 상승(관리자 그룹 추가, 처음 보는 주소·직후의 관리자 명령, 업무 시간 밖의 권한 사용, 다른 계정의 권한 사용)이 뚜렷하게 확인되고, 세션을 거둘 계정이 올바른 경우뿐입니다.
// 평소 주소의 관리자 명령 한 번·실패하거나 취소된 시도·관리자가 아닌 그룹 변경 같은 애매한 경보와 Wazuh 규칙 수준 4~9의 한 번짜리 의심 경보는 알림까지만 합니다. 수준 3 이하는 기록만 합니다.
// 반복 건수(data.count)와 계정 이름의 종류는 출처에 근거가 없어 확신도에 쓰지 않습니다.

// 패턴 목록: xdr/privilege/patterns.json 과 같은 내용입니다(시험이 두 곳이 같은지 비교합니다).
// 근거는 MITRE ATT&CK T1078(보조 T1068)이고, 문구의 모양과 점수는 이 수업의 학생 기준(로컬 추정)입니다.
// PATTERNS-BEGIN
const PATTERNS_FILE = {
  "version": 1,
  "basis": {
    "technique": "T1078",
    "name": "Valid Accounts",
    "url": "https://attack.mitre.org/techniques/T1078/",
    "relatedTechniques": [
      "T1068"
    ],
    "checkedAt": "2026-10-15",
    "checked": [
      "https://attack.mitre.org/techniques/T1078/ (정상 계정의 자격으로 최초 접근·지속·권한 상승에 쓰이고, 탐지는 평소와 다른 시각·위치의 로그온 패턴을 본다)",
      "https://attack.mitre.org/techniques/T1068/ (소프트웨어 취약점을 악용한 권한 상승, 탐지는 취약한 드라이버·OS 구성요소 악용 시도와 이어지는 이상 프로세스·토큰 동작을 본다)"
    ],
    "notChecked": "두 페이지는 읽기 도구가 만든 요약으로 확인했고 원문 전체를 직접 읽지는 못했습니다. T1078의 탐지 설명에는 관리자 그룹 변경이 나오지 않았고, T1068의 탐지는 취약점 악용 흔적(드라이버·setuid 등)을 보는데 이 경보 묶음에는 그런 흔적이 없습니다.",
    "note": "이 경보 묶음은 취약점 악용이 아니라 계정·그룹 변경과 관리자 명령 사용을 보여 주므로, 패턴의 주된 근거는 T1078입니다. T1068은 '이어지는 이상 토큰 동작'이라는 탐지 관점으로만 곁들이며, 취약점 악용 패턴은 넣지 않았습니다. 관리자 그룹 추가·설명 문구의 모양·점수는 수업용 경보 묶음을 보고 정한 로컬 추정입니다. 경보에는 구조화된 칸(그룹 이름 외)이 없어 설명 문구(rule.description)와 data.group을 봅니다."
  },
  "patterns": [
    {
      "name": "admin_group_added",
      "technique": "T1078",
      "condition": "평소 관리자가 아닌 계정이 관리자 그룹에 추가됐거나, 관리자 그룹에서 빠진 계정이 다시 들어왔다. 관리자 그룹이 아닌 그룹 추가나 새 일반 그룹 생성은 맞지 않는다.",
      "fields": [
        "rule.description",
        "data.group",
        "data.srcip"
      ],
      "alertOnly": false,
      "evidence": "T1078은 공격자가 훔친 정상 계정이 더 높은 권한을 얻어 권한 상승에 쓰일 수 있다고 설명한다(관리자 그룹 변경 자체는 출처에 나오지 않는 로컬 추정).",
      "source": "https://attack.mitre.org/techniques/T1078/"
    },
    {
      "name": "admin_use_unfamiliar_or_sudden",
      "technique": "T1078",
      "condition": "처음 보는 주소에서 관리자 명령이나 관리자 권한 전환이 있거나, 관리자가 된 직후 곧바로 관리자 명령이 실행됐다. 평소 주소에서 관리자 명령이 한 번 실행된 경우, 실패로 끝난 경우, 취소된 권한 창은 맞지 않는다.",
      "fields": [
        "rule.description",
        "data.srcip"
      ],
      "alertOnly": false,
      "evidence": "T1078의 탐지는 평소와 다른 위치·출처의 로그온과 계정 사용을 본다고 설명하고, T1068의 탐지는 권한 상승 뒤 이어지는 이상 토큰 동작을 본다고 설명한다.",
      "source": "https://attack.mitre.org/techniques/T1078/"
    },
    {
      "name": "admin_use_off_hours",
      "technique": "T1078",
      "condition": "수업 시간 밖이나 업무처럼 보이지 않는 시각에 관리자 그룹 추가나 관리자 명령이 있다. 수업 시간 안의 권한 사용은 맞지 않는다.",
      "fields": [
        "rule.description",
        "data.srcip"
      ],
      "alertOnly": false,
      "evidence": "T1078의 탐지는 서비스 계정이나 사용자가 평소와 다른 시각에 로그인하는 비정상 패턴을 본다고 설명한다.",
      "source": "https://attack.mitre.org/techniques/T1078/"
    },
    {
      "name": "other_account_privilege_use",
      "technique": "T1078",
      "condition": "자기 계정이 아닌 다른 계정의 권한으로 관리자 명령이 실행됐다.",
      "fields": [
        "rule.description",
        "data.srcip"
      ],
      "alertOnly": false,
      "evidence": "T1078은 공격자가 이미 있는 다른 계정의 자격을 써서 권한을 얻는다고 설명한다(설명 문구의 모양은 로컬 추정이며, T1068의 이상 토큰 동작은 간접 근거일 뿐이다).",
      "source": "https://attack.mitre.org/techniques/T1078/"
    }
  ],
  "notPrivilegeAbuse": {
    "condition": "수업 시간 안의 권한 상승 창 하나가 취소된 경우, 관리자가 아닌 과제 그룹이나 새 일반 그룹, 평소 주소에서의 관리자 명령 한 번, 실패로 끝난 관리자 명령, 읽기만 한 그룹 조회, 수업용 관리 계정·서비스 계정의 평소 로그인·로그아웃, 비밀번호 변경, 세션 조회는 권한 가로채기로 보지 않는다.",
    "evidence": "출처가 말하는 악용은 평소와 다른 위치·시각·계정으로 높은 권한을 얻거나 쓰는 것이므로, 평소 주소·시각의 일상 활동이나 권한이 바뀌지 않은 경우는 해당하지 않는다."
  }
};
// PATTERNS-END

const PATTERNS = PATTERNS_FILE.patterns;
const byName = (name) => PATTERNS.find((pattern) => pattern.name === name);
const GROUP = byName('admin_group_added');
const UNFAMILIAR = byName('admin_use_unfamiliar_or_sudden');
const OFF_HOURS = byName('admin_use_off_hours');
const OTHER = byName('other_account_privilege_use');

// 확신도 기준: 0.85 이상 block, 0.5 이상 alert, 그 아래 record.
const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const ONE_PATTERN = 0.88;    // 패턴 하나가 뚜렷하게 맞음
const TWO_PATTERNS = 0.93;   // 서로 다른 패턴 둘이 한 경보에 맞음
const MANY_PATTERNS = 0.96;  // 셋 이상
const ALERT_ONLY_CAP = 0.84;
const LEVEL_BAND = Object.freeze({ min: 4, max: 9 }); // 심판 안내를 반영한 학생 기준: 한 번짜리 의심 이벤트는 알림
const HIGH_LEVEL = 10;       // 이 수준 이상인데 패턴을 못 찾으면 사람이 보게 알림
const MAX_TEXT = 2000;

// 설명 문구의 표현(경보에 구조화된 칸이 없어 문구를 봅니다).
// '명령은 없습니다', '추가되지 않았습니다' 같은 부정 표현은 먼저 걷어냅니다.
const NEGATED = /(?:관리자 )?(?:명령|그룹 추가|권한 전환|권한 상승|실행)(?:은|는|이|가)?\s*(?:없습니다|아닙니다)|(?:추가|실행|들어가|들어오|전환)(?:되|하)?지\s*(?:않|못)\S*/gu;
const GROUP_ADDED = /관리자 그룹(?:에)?\s*(?:추가|들어)|다시 관리자로 들어/u;
const ADMIN_COMMAND = /관리자 명령|권한 명령/u;
const PRIV_SWITCH = /관리자 권한으로 바뀌/u;
const NEW_ADDRESS = /처음 보는 주소|주소는 처음/u;
const SUDDEN = /방금 관리자가 된|곧바로|직후/u;
const OFF_TIME = /수업 시간 밖|업무처럼 보이지 않는 시각/u;
const OTHER_ACCOUNT = /다른 계정의 권한/u;
const FAILED = /실패|취소/u;

const round2 = (value) => Math.round(value * 100) / 100;

// 세션을 거둘 수 있는 계정: 영문자·숫자·점·밑줄·붙임표로 된 이름 하나.
function isAccount(value) {
  return typeof value === 'string' && /^[A-Za-z0-9._-]{1,64}$/u.test(value);
}

function readLevel(value) {
  const level = typeof value === 'number' ? value : (typeof value === 'string' && /^\d{1,2}$/u.test(value.trim()) ? Number(value) : NaN);
  return Number.isInteger(level) ? level : null;
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
  const rawDescription = typeof alert.rule?.description === 'string' ? alert.rule.description : '';
  if (rawDescription.length > MAX_TEXT) return result(0, '맞는 패턴 없음: 설명을 읽을 수 없어 기록만 합니다.');
  const description = rawDescription.replace(/\s+/gu, ' ').replace(NEGATED, ' ');
  const level = readLevel(alert.rule?.level);

  const groupAdded = GROUP_ADDED.test(description);
  const adminCommand = ADMIN_COMMAND.test(description);
  const failed = FAILED.test(description);
  const names = [];
  if (groupAdded) names.push(GROUP.name);
  if (!failed && ((NEW_ADDRESS.test(description) && (adminCommand || PRIV_SWITCH.test(description)))
    || (SUDDEN.test(description) && adminCommand))) names.push(UNFAMILIAR.name);
  if (OFF_TIME.test(description) && (groupAdded || adminCommand)) names.push(OFF_HOURS.name);
  if (!failed && OTHER_ACCOUNT.test(description) && adminCommand) names.push(OTHER.name);

  let confidence;
  let note;
  if (names.length) {
    confidence = names.length > 2 ? MANY_PATTERNS : names.length > 1 ? TWO_PATTERNS : ONE_PATTERN;
    if (!isAccount(data.srcuser)) {
      confidence = Math.min(confidence, ALERT_ONLY_CAP);
      note = ' 세션을 거둘 계정이 올바르지 않아 막지 않고 사람이 확인합니다.';
    } else {
      note = ' 평소와 다른 권한 상승의 뚜렷한 표현이 있어 막습니다.';
    }
    confidence = round2(confidence);
  } else if (level !== null && level >= LEVEL_BAND.min && level <= LEVEL_BAND.max) {
    names.push('single_suspicious_event');
    confidence = ALERT_AT;
    note = ' 뚜렷한 패턴은 없지만 한 번짜리 의심 이벤트(수준 4~9)라 알림만 합니다.';
  } else if (level !== null && level >= HIGH_LEVEL) {
    names.push('high_level_unmatched');
    confidence = ALERT_AT;
    note = ' 수준은 높지만 맞는 패턴을 찾지 못해 사람이 확인합니다.';
  } else {
    return result(0, '맞는 패턴 없음: 평소와 다른 권한 상승의 흔적이 없어 기록만 합니다.');
  }
  return result(confidence, `${names.join(' + ')}:${note}`);
}
