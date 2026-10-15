// 몰래 심어진 프로그램(서비스·예약 작업·시작 항목) 생성 경보를 block / alert / record로 나눕니다.
// 이 파일은 혼자 계산합니다: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않습니다.
// 경보 원본은 고치지 않습니다. 같은 경보에는 항상 같은 답을 냅니다(저장된 상태 없음).
// 판정기 규칙을 대신하지 않고, 확인 단계 하나로 불러 쓰는 부품입니다.
//
// 막는 것은 새로 만든 서비스·예약 작업·시작 항목이 서명 없음이나 평소 목록에 없음 같은 뚜렷한 표현과 함께 확인되고, 막을 주소가 올바른 경우뿐입니다.
// 수업 도구·설명만 바뀐 서비스·실행 기록이 없는 시작 폴더 변경·임시 폴더 파일 하나 같은 애매한 경보와 Wazuh 규칙 수준 4~9의 한 번짜리 의심 경보는 알림까지만 합니다. 수준 3 이하는 기록만 합니다.
// 반복 건수(data.count)와 계정(srcuser)은 출처에 근거가 없어 확신도에 쓰지 않습니다.

// 패턴 목록: xdr/persistence/patterns.json 과 같은 내용입니다(시험이 두 곳이 같은지 비교합니다).
// 근거는 MITRE ATT&CK T1543·T1053(보조 T1547.001)이고, 문구의 모양과 점수는 이 수업의 학생 기준(로컬 추정)입니다.
// PATTERNS-BEGIN
const PATTERNS_FILE = {
  "version": 1,
  "basis": {
    "technique": "T1543",
    "name": "Create or Modify System Process",
    "url": "https://attack.mitre.org/techniques/T1543/",
    "relatedTechniques": ["T1053", "T1547.001"],
    "checkedAt": "2026-10-15",
    "checked": [
      "https://attack.mitre.org/techniques/T1543/ (서비스 생성·수정으로 반복 실행, 탐지는 서비스 생성·변경)",
      "https://attack.mitre.org/techniques/T1053/ (예약 작업으로 최초·반복 실행, 탐지는 새 작업 생성과 이상 프로세스)",
      "https://attack.mitre.org/techniques/T1547.001/ (시작 폴더·Run 키로 로그온 때 자동 실행)"
    ],
    "notChecked": "T1547.001 페이지는 앞부분 100000자만 읽었고 탐지 항목의 세부는 확인하지 못했습니다.",
    "note": "경보에는 서명·평소 목록을 나타내는 구조화된 칸이 없어 설명 문구(rule.description)와 실행 파일 경로(data.path)를 봅니다. 출처는 '서명 없음'을 탐지 항목이 아닌 완화책(코드 서명 제한)으로만 다루고, '임시 폴더'는 세 출처 모두에 직접 나오지 않습니다. 그래서 이 둘과 문구의 모양은 수업용 경보 묶음을 보고 정한 로컬 추정이며, 임시 폴더는 독립 패턴 없이 보조 조건으로만 씁니다."
  },
  "patterns": [
    {
      "name": "service_unsigned_new_or_changed",
      "technique": "T1543",
      "condition": "서비스가 새로 등록됐거나 서비스 실행 파일이 바뀌었고, 설명에 서명이 없다는 말이 있거나 평소 목록에 없다는 말이 있다.",
      "fields": [
        "rule.description",
        "data.path",
        "data.srcip"
      ],
      "helpers": ["temp_folder_path"],
      "alertOnly": false,
      "evidence": "T1543은 공격자가 서비스를 새로 설치하거나 기존 것을 고쳐 부팅 때나 주기적으로 악성 페이로드를 반복 실행하게 만든다고 설명하고, 탐지는 서비스의 생성과 변경을 본다.",
      "source": "https://attack.mitre.org/techniques/T1543/"
    },
    {
      "name": "scheduled_task_unfamiliar",
      "technique": "T1053",
      "condition": "평소 목록에 없는 새 예약 작업이 만들어졌고, 설명에 임의 문자열 이름, 수업 시간 밖 실행, 임시 파일을 가리킴 중 하나가 있다. 수업 시간 안의 단순 예약 작업 하나는 맞지 않는다.",
      "fields": [
        "rule.description",
        "data.path",
        "data.srcip"
      ],
      "helpers": ["temp_folder_path"],
      "alertOnly": false,
      "evidence": "T1053은 공격자가 예약 작업 기능으로 악성 코드를 최초 또는 반복 실행해 지속성을 얻는다고 설명하고, 탐지는 새 예약 작업의 생성과 그 작업에 연결된 이상 프로세스를 본다.",
      "source": "https://attack.mitre.org/techniques/T1053/"
    },
    {
      "name": "startup_folder_added",
      "technique": "T1547.001",
      "condition": "시작 폴더에 평소 목록에 없는 프로그램이 추가됐다. 폴더 변경만 있고 이어서 실행된 기록이 없거나 수업 도구 이름만 있는 경우는 맞지 않는다.",
      "fields": [
        "rule.description",
        "data.path",
        "data.srcip"
      ],
      "helpers": ["temp_folder_path"],
      "alertOnly": false,
      "evidence": "T1547.001은 공격자가 프로그램을 시작 폴더에 넣어 사용자가 로그인할 때 자동 실행되게 한다고 설명한다(T1543·T1053 밖의 보조 근거).",
      "source": "https://attack.mitre.org/techniques/T1547/001/"
    }
  ],
  "helperSignals": {
    "temp_folder_path": {
      "condition": "data.path가 사용자 폴더 아래 Temp 폴더에 있는 실행 파일을 가리킨다. 이 신호 하나로는 패턴이 되지 않고 위 세 패턴의 확신을 높이는 보조 조건으로만 쓴다.",
      "evidence": "출처에 직접 나오지 않는 로컬 추정이다. T1543의 탐지가 서비스 파일이 평소와 다른 위치에 생기는 것을 간접적으로 본다는 점에만 기댄다.",
      "source": "https://attack.mitre.org/techniques/T1543/"
    }
  },
  "notPersistence": {
    "condition": "수업 중 예약 작업 하나, 수업 도구 이름만 있는 시작 항목, 서비스 설명만 바뀐 경우, 서비스가 멈췄다 같은 파일로 다시 시작된 경우, 서명된 기존 서비스, 평소 시각의 업데이트 예약, 읽기만 한 경우는 심어진 프로그램으로 보지 않는다.",
    "evidence": "출처가 말하는 지속성은 새로 만들거나 고친 서비스·예약 작업·시작 항목이 반복 실행되게 하는 것이므로, 새 항목을 만들지 않았거나 평소 목록의 기존 항목은 해당하지 않는다."
  }
};
// PATTERNS-END

const PATTERNS = PATTERNS_FILE.patterns;
const byName = (name) => PATTERNS.find((pattern) => pattern.name === name);
const SERVICE = byName('service_unsigned_new_or_changed');
const TASK = byName('scheduled_task_unfamiliar');
const STARTUP = byName('startup_folder_added');
const HELPER_NAME = 'temp_folder_path';

// 확신도 기준: 0.85 이상 block, 0.5 이상 alert, 그 아래 record.
const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const ONE_PATTERN = 0.88;    // 패턴 하나가 뚜렷하게 맞음
const TWO_PATTERNS = 0.93;   // 서로 다른 패턴 둘 이상이 한 경보에 맞음
const TEMP_BONUS = 0.03;     // 실행 파일이 임시 폴더에 있으면 더함
const STRONG_CAP = 0.97;
const ALERT_ONLY_CAP = 0.84;
const TEMP_ALONE = 0.55;     // 임시 폴더 실행 파일만 있고 패턴은 안 맞음
const LEVEL_BAND = Object.freeze({ min: 4, max: 9 }); // 심판 안내를 반영한 학생 기준: 한 번짜리 의심 이벤트는 알림
const HIGH_LEVEL = 10;       // 이 수준 이상인데 패턴을 못 찾으면 사람이 보게 알림
const MAX_TEXT = 2000;

// 설명 문구의 표현(경보에 구조화된 칸이 없어 문구를 봅니다).
const NEGATED = /(?:서비스 )?(?:등록|기록|변경)(?:은|는)\s*없습니다/gu; // '서비스 등록은 없습니다' 같은 부정 표현은 먼저 걷어냅니다.
const SERVICE_NEW = /새 서비스|서비스 등록|서비스[^.]{0,20}등록됐|실행 파일이 바뀌/u;
const UNSIGNED = /서명 없|서명이 없/u;
const NOT_USUAL = /평소 목록에 없|처음 보는/u;
const TASK_WORD = /예약 작업/u;
const TASK_ODD = /처음 보는|임의 문자열|수업 시간 밖|임시 (?:파일|폴더)/u;
const STARTUP_WORD = /시작 (?:폴더|프로그램|항목)/u;
const STARTUP_ADDED = /추가됐|가리킵니다/u;
const TEMP_TEXT = /임시 (?:파일|폴더)/u;
const TEMP_PATH = /[\\/]temp[\\/]/u;

const round2 = (value) => Math.round(value * 100) / 100;

// 올바른 출발 주소만 막을 수 있습니다: IPv4 한 개 또는 IPv6 한 개.
function isAddress(value) {
  if (typeof value !== 'string') return false;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u.exec(value);
  if (v4) return v4.slice(1).every((part) => Number(part) <= 255);
  return value.length <= 45 && value.includes(':') && /^[0-9a-f:]+$/iu.test(value);
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
  const present = (value) => value !== undefined && value !== null;
  const rawPath = typeof data.path === 'string' && data.path.length <= MAX_TEXT ? data.path.toLowerCase() : '';
  if (present(data.path) && typeof data.path !== 'string') {
    return result(0, '맞는 패턴 없음: 실행 파일 경로를 읽을 수 없어 기록만 합니다.');
  }
  const rawDescription = typeof alert.rule?.description === 'string' ? alert.rule.description : '';
  if (rawDescription.length > MAX_TEXT) return result(0, '맞는 패턴 없음: 설명을 읽을 수 없어 기록만 합니다.');
  const description = rawDescription.replace(/\s+/gu, ' ').replace(NEGATED, ' ');
  const level = readLevel(alert.rule?.level);

  const tempPath = TEMP_PATH.test(rawPath);
  const names = [];
  if (SERVICE_NEW.test(description) && (UNSIGNED.test(description) || NOT_USUAL.test(description))) names.push(SERVICE.name);
  if (TASK_WORD.test(description) && TASK_ODD.test(description)) names.push(TASK.name);
  if (STARTUP_WORD.test(description) && STARTUP_ADDED.test(description) && (NOT_USUAL.test(description) || TEMP_TEXT.test(description))) names.push(STARTUP.name);

  let confidence;
  let note;
  if (names.length) {
    confidence = names.length > 1 ? TWO_PATTERNS : ONE_PATTERN;
    if (tempPath) { names.push(HELPER_NAME); confidence += TEMP_BONUS; }
    confidence = round2(Math.min(STRONG_CAP, confidence));
    if (!isAddress(data.srcip)) {
      confidence = Math.min(confidence, ALERT_ONLY_CAP);
      note = ' 격리할 주소가 올바르지 않아 막지 않고 사람이 확인합니다.';
    } else {
      note = ' 새로 심은 프로그램의 뚜렷한 표현이 있어 막습니다.';
    }
  } else if (tempPath) {
    names.push(HELPER_NAME);
    confidence = TEMP_ALONE;
    note = ' 임시 폴더 실행 파일만 있고 등록은 확인되지 않아 알림만 합니다.';
  } else if (level !== null && level >= LEVEL_BAND.min && level <= LEVEL_BAND.max) {
    names.push('single_suspicious_event');
    confidence = ALERT_AT;
    note = ' 뚜렷한 패턴은 없지만 한 번짜리 의심 이벤트(수준 4~9)라 알림만 합니다.';
  } else if (level !== null && level >= HIGH_LEVEL) {
    names.push('high_level_unmatched');
    confidence = ALERT_AT;
    note = ' 수준은 높지만 맞는 패턴을 찾지 못해 사람이 확인합니다.';
  } else {
    return result(0, '맞는 패턴 없음: 새로 심은 흔적이 없어 기록만 합니다.');
  }
  return result(confidence, `${names.join(' + ')}:${note}`);
}
