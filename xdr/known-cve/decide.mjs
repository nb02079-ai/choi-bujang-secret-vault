// 알려진 취약점(CVE-2021-44228, Log4j JNDI 조회) 악용 경보를 block / alert / record로 나눕니다.
// 이 파일은 혼자 계산합니다: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않습니다.
// 경보 원본은 고치지 않습니다. 같은 경보에는 항상 같은 답을 냅니다(저장된 상태 없음).
// 판정기 규칙을 대신하지 않고, 확인 단계 하나로 불러 쓰는 부품입니다.
//
// 막는 것은 머리글이나 요청 인자에 원격 주소가 이어지는 완전한 조회 구문이 있고, 막을 주소가 올바른 경우뿐입니다.
// 단어·번호·조각만 있는 경우, 점검 흔적만 있는 경우, Wazuh 규칙 수준 4~9의 한 번짜리 의심 경보는 알림까지만 합니다. 수준 3 이하는 기록만 합니다.
// 반복 건수(data.count)는 출처에 근거가 없어 확신도에 쓰지 않습니다.

// 패턴 목록: xdr/known-cve/patterns.json 과 같은 내용입니다(시험이 두 곳이 같은지 비교합니다).
// 근거는 MITRE ATT&CK T1190 과 CVE-2021-44228 이고, 문자열 모양과 점수는 이 수업의 학생 기준(로컬 추정)입니다.
// PATTERNS-BEGIN
const PATTERNS_FILE = {
  "version": 1,
  "basis": {
    "technique": "T1190",
    "name": "Exploit Public-Facing Application",
    "url": "https://attack.mitre.org/techniques/T1190/",
    "vulnerability": "CVE-2021-44228",
    "vulnerabilityName": "Apache Log4j 2 JNDI 조회(Log4Shell)",
    "checkedAt": "2026-10-15",
    "checked": [
      "https://attack.mitre.org/techniques/T1190/ (CVE-2021-44228 악용 사례 언급 확인)",
      "https://attack.mitre.org/techniques/T1595/002/ (취약점 점검 기법 설명 확인)",
      "https://logging.apache.org/log4j/2.x/security.html (CVE-2021-44228 악용 방식 확인)"
    ],
    "notChecked": "NVD의 CVE-2021-44228 상세 페이지는 본문이 열리지 않아 근거로 쓰지 않았습니다.",
    "note": "조건의 문자열 모양(조회 구문의 시작 글자, 반복 기준)은 수업용 경보 묶음을 보고 정한 로컬 추정이며, 위 출처가 정한 값이 아닙니다."
  },
  "patterns": [
    {
      "name": "jndi_lookup_in_header",
      "technique": "T1190",
      "vulnerability": "CVE-2021-44228",
      "condition": "요청 머리글(data.useragent)에 달러 기호와 중괄호로 열고 jndi: 로 시작해 원격 주소(ldap 등)가 이어지는 완전한 조회 구문이 있다.",
      "fields": [
        "data.srcip",
        "data.useragent"
      ],
      "alertOnly": false,
      "evidence": "Log4j 2 보안 안내는 로그 메시지나 그 파라미터를 통제할 수 있는 공격자가 LDAP 같은 JNDI 엔드포인트를 지정해 원격에서 읽어 온 코드를 실행하게 만든다고 설명하며, 머리글은 서버가 로그로 남기는 값이라 그 입력이 된다.",
      "source": "https://logging.apache.org/log4j/2.x/security.html"
    },
    {
      "name": "jndi_lookup_in_param",
      "technique": "T1190",
      "vulnerability": "CVE-2021-44228",
      "condition": "요청 인자(data.url의 쿼리)에 달러 기호와 중괄호로 열고 jndi: 로 시작해 원격 주소(ldap 등)가 이어지는 완전한 조회 구문이 있다.",
      "fields": [
        "data.srcip",
        "data.url"
      ],
      "alertOnly": false,
      "evidence": "Log4j 2 보안 안내는 로그 메시지 파라미터를 통제하는 공격자가 JNDI 엔드포인트를 지정할 수 있다고 하며, 주소의 쿼리 인자는 공개 서비스가 로그로 남기는 외부 입력이다. T1190은 이렇게 공개된 응용의 약점을 악용하는 초기 침투 기법이고 Log4Shell 악용 사례가 언급돼 있다.",
      "source": "https://attack.mitre.org/techniques/T1190/"
    },
    {
      "name": "scanner_probe_trace",
      "technique": "T1595.002",
      "vulnerability": "CVE-2021-44228",
      "condition": "요청 주소에 점검용 인자(probe)가 있거나 알려진 취약점 점검 도구의 이름 흔적이 있다. 이 신호 하나로는 막지 않고, 위 두 조회 구문 패턴과 한 요청에 함께 있을 때 확신을 높이는 보조 신호로만 쓴다.",
      "fields": [
        "data.srcip",
        "data.url"
      ],
      "alertOnly": true,
      "supports": [
        "jndi_lookup_in_header",
        "jndi_lookup_in_param"
      ],
      "evidence": "T1595.002는 공격자가 널리 알려진 취약점을 찾으려고 대상을 점검하고 그 결과를 T1190 같은 초기 침투에 쓴다고 설명하므로, 점검 흔적은 악용 시도와 이어질 수 있다. 다만 출처가 도구 이름이나 인자 이름을 정해 주지는 않아 단독으로는 알림에 그친다.",
      "source": "https://attack.mitre.org/techniques/T1595/002/"
    }
  ],
  "notExploit": {
    "condition": "CVE 번호나 jndi 같은 단어만 있는 경우, 중괄호가 한 번 있는 경우, 조회 구문이 중간에 잘린 경우, 점검 도구와 비슷한 수업용 프로그램 이름만 있는 경우는 악용 형태로 보지 않는다.",
    "evidence": "Log4j 2 보안 안내가 말하는 악용은 공격자가 JNDI 엔드포인트를 지정한 값이 로그에 들어가 조회되는 경우이므로, 엔드포인트를 가리키지 않는 단어나 조각은 조회를 일으키는 형태가 아니다."
  }
};
// PATTERNS-END

const PATTERNS = PATTERNS_FILE.patterns;
const byName = (name) => PATTERNS.find((pattern) => pattern.name === name);
const HEADER = byName('jndi_lookup_in_header');
const PARAM = byName('jndi_lookup_in_param');
const SCANNER = byName('scanner_probe_trace');

// 확신도 기준: 0.85 이상 block, 0.5 이상 alert, 그 아래 record.
const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const ONE_PLACE = 0.88;      // 머리글이나 인자 한 곳에 완전한 조회 구문
const BOTH_PLACES = 0.93;    // 머리글과 인자 두 곳에 같은 구문
const SCANNER_BONUS = 0.03;  // 점검 흔적이 함께 있으면 더함
const STRONG_CAP = 0.97;
const ALERT_ONLY_CAP = 0.84; // 알림까지만 하는 경우의 상한
const SCANNER_ALONE = 0.55;  // 점검 흔적만 있는 경우
const LEVEL_BAND = Object.freeze({ min: 4, max: 9 }); // 심판 안내를 반영한 학생 기준: 한 번짜리 의심 이벤트는 알림
const HIGH_LEVEL = 10;       // 이 수준 이상인데 구문을 못 찾으면 사람이 보게 알림
const MAX_TEXT = 2000;

// 완전한 조회 구문: 달러 기호+중괄호로 열고 jndi: 다음에 scheme://원격주소가 이어지는 모양.
// 'CVE-2021-44228', 'jndi' 같은 단어만 있거나, 중괄호만 있거나, 중간에 잘린 조각은 맞지 않습니다.
const LOOKUP = /\$\{\s*jndi\s*:\s*[a-z][a-z0-9+.-]{1,9}:\/\/[^\s}]+/u;
// 점검 흔적: 주소의 probe 인자, 또는 설명에 '점검 흔적'이 있는 경우.
const PROBE_PARAM = /[?&]probe=/u;
const PROBE_CUE = /점검 흔적/u;

const round2 = (value) => Math.round(value * 100) / 100;

function decodedText(value) {
  if (typeof value !== 'string' || value.length > MAX_TEXT) return null;
  let text = value;
  for (let round = 0; round < 2; round += 1) {
    try { text = decodeURIComponent(text); } catch { break; }
  }
  return text.toLowerCase();
}

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
  const header = decodedText(data.useragent);
  const url = decodedText(data.url);
  if ((present(data.useragent) && header === null) || (present(data.url) && url === null)) {
    return result(0, '맞는 패턴 없음: 머리글이나 요청 주소를 읽을 수 없어 기록만 합니다.');
  }
  const description = typeof alert.rule?.description === 'string' ? alert.rule.description : '';
  const level = readLevel(alert.rule?.level);

  const inHeader = Boolean(header) && LOOKUP.test(header);
  const inParam = Boolean(url) && LOOKUP.test(url);
  const probe = (Boolean(url) && PROBE_PARAM.test(url)) || PROBE_CUE.test(description);

  const names = [];
  let confidence = 0;
  let note;
  if (inHeader || inParam) {
    if (inHeader) names.push(HEADER.name);
    if (inParam) names.push(PARAM.name);
    confidence = inHeader && inParam ? BOTH_PLACES : ONE_PLACE;
    if (probe) { names.push(SCANNER.name); confidence += SCANNER_BONUS; }
    confidence = round2(Math.min(STRONG_CAP, confidence));
    if (!isAddress(data.srcip)) {
      confidence = Math.min(confidence, ALERT_ONLY_CAP);
      note = ' 막을 주소가 올바르지 않아 막지 않고 사람이 확인합니다.';
    } else {
      note = ' 원격 주소가 이어지는 완전한 조회 구문이라 막습니다.';
    }
  } else if (probe) {
    names.push(SCANNER.name);
    confidence = SCANNER_ALONE;
    note = ' 점검 흔적만 있고 조회 구문은 없어 알림만 합니다.';
  } else if (level !== null && level >= LEVEL_BAND.min && level <= LEVEL_BAND.max) {
    names.push('single_suspicious_event');
    confidence = ALERT_AT;
    note = ' 조회 구문은 없지만 한 번짜리 의심 이벤트(수준 4~9)라 알림만 합니다.';
  } else if (level !== null && level >= HIGH_LEVEL) {
    names.push('high_level_unmatched');
    confidence = ALERT_AT;
    note = ' 수준은 높지만 맞는 구문을 찾지 못해 사람이 확인합니다.';
  } else {
    return result(0, '맞는 패턴 없음: 조회 구문이나 점검 흔적이 없어 기록만 합니다.');
  }
  return result(confidence, `${names.join(' + ')}:${note}`);
}
