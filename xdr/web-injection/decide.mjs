// 웹 접근 경보에서 SQL 구문·스크립트 태그·경로 거슬러 올라가기(../)·명령 구분자 형태를 가려내 block / alert / record로 나눕니다.
// 이 파일은 혼자 계산합니다: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않습니다.
// 경보 원본은 고치지 않습니다. 같은 경보에는 항상 같은 답을 냅니다(저장된 상태 없음).
// 판정기 규칙을 대신하지 않고, 확인 단계 하나로 불러 쓰는 부품입니다.
//
// 막는 것은 SQL·스크립트·경로 거슬러 올라가기·명령 구분자가 같은 주소에서 반복된 명확한 경우뿐입니다.
// 한 번뿐인 의심 표기, 반복 기준 미만, Wazuh 규칙 수준 4~9의 한 번짜리 웹 요청 경보는 알림까지만 합니다. 수준 3 이하(성공·허가된 이벤트)는 기록만 합니다.

// 패턴 목록: xdr/web-injection/patterns.json 과 같은 내용입니다(시험이 두 곳이 같은지 비교합니다).
// 근거는 MITRE ATT&CK T1190 이고, 약점의 모양은 CWE-89·79·22·78 로 설명합니다. thresholds 의 숫자는 이 수업의 학생 기준입니다.
// PATTERNS-BEGIN
const PATTERNS = [
    {
      "name": "sql_injection_repeated",
      "technique": "T1190",
      "weakness": "CWE-89",
      "condition": "요청 인자(data.url의 쿼리) 안에 SQL 구문을 이어 붙인 형태가 있고, 같은 주소에서 반복되어 경보의 data.count가 5건 이상이다.",
      "fields": [
        "data.srcip",
        "data.url",
        "data.count"
      ],
      "thresholds": {
        "repeats": 5
      },
      "alertOnly": false,
      "evidence": "T1190은 인터넷에 열린 응용의 약점을 악용해 처음 침투하는 기법(SQL 주입 언급)이고, CWE-89(SQL Injection)는 외부 입력으로 SQL 명령을 만들면서 명령을 바꿀 수 있는 특수 요소를 걸러 내지 않는 그 약점이다.",
      "source": "https://attack.mitre.org/techniques/T1190/",
      "weaknessSource": "https://cwe.mitre.org/data/definitions/89.html"
    },
    {
      "name": "script_injection_repeated",
      "technique": "T1190",
      "weakness": "CWE-79",
      "condition": "요청 인자(data.url의 쿼리) 안에 스크립트 태그를 끼워 넣은 형태가 있고, 같은 주소에서 반복되어 경보의 data.count가 5건 이상이다.",
      "fields": [
        "data.srcip",
        "data.url",
        "data.count"
      ],
      "thresholds": {
        "repeats": 5
      },
      "alertOnly": false,
      "evidence": "T1190은 인터넷에 열린 응용의 약점을 악용해 처음 침투하는 기법이고, CWE-79(Cross-site Scripting)는 사용자가 조작할 수 있는 입력을 다른 사용자에게 보여 줄 웹 페이지 출력에 넣기 전에 걸러 내지 않는 그 약점이다.",
      "source": "https://attack.mitre.org/techniques/T1190/",
      "weaknessSource": "https://cwe.mitre.org/data/definitions/79.html"
    },
    {
      "name": "path_traversal_repeated",
      "technique": "T1190",
      "weakness": "CWE-22",
      "condition": "요청 인자(data.url의 쿼리) 안에 경로를 거슬러 올라가는 ../ 형태가 있고, 같은 주소에서 반복되어 경보의 data.count가 5건 이상이다.",
      "fields": [
        "data.srcip",
        "data.url",
        "data.count"
      ],
      "thresholds": {
        "repeats": 5
      },
      "alertOnly": false,
      "evidence": "T1190은 인터넷에 열린 응용의 약점을 악용해 처음 침투하는 기법이고, CWE-22(Path Traversal)는 외부 입력으로 만든 경로의 특수 요소를 걸러 내지 않아 제한된 디렉터리 밖의 위치로 풀리게 하는 그 약점이다.",
      "source": "https://attack.mitre.org/techniques/T1190/",
      "weaknessSource": "https://cwe.mitre.org/data/definitions/22.html"
    },
    {
      "name": "command_separator_repeated",
      "technique": "T1190",
      "weakness": "CWE-78",
      "condition": "요청 인자(data.url의 쿼리) 안에 운영체제 명령을 이어 붙이는 구분자 형태가 있고, 같은 주소에서 반복되어 경보의 data.count가 5건 이상이다. 처음 지시한 신호(SQL·스크립트·../) 밖이었으나 학생이 막기 대상으로 추가했다.",
      "fields": [
        "data.srcip",
        "data.url",
        "data.count"
      ],
      "thresholds": {
        "repeats": 5
      },
      "alertOnly": false,
      "evidence": "T1190은 인터넷에 열린 응용의 약점을 악용해 처음 침투하는 기법이고, CWE-78(OS Command Injection)은 외부 입력으로 운영체제 명령을 만들면서 명령을 바꿀 수 있는 특수 요소를 걸러 내지 않는 그 약점이다.",
      "source": "https://attack.mitre.org/techniques/T1190/",
      "weaknessSource": "https://cwe.mitre.org/data/definitions/78.html"
    },
    {
      "name": "single_injection_like_attempt",
      "technique": "T1190",
      "weakness": null,
      "condition": "주입처럼 보이는 표기가 있지만 반복 기준(5건) 미만이거나, 설명에 따옴표·구분 문자·주입처럼 보이는 표기가 한 번 있다고 적혀 있다. 막지 않고 알림만 한다.",
      "fields": [
        "data.url",
        "data.count",
        "rule.description"
      ],
      "thresholds": {},
      "alertOnly": true,
      "evidence": "T1190의 감지 지침은 접근 로그에서 공격 입력처럼 보이는 의심스러운 URL·매개변수 구조를 살펴보라고 하며, 한 번뿐인 표기는 반복이 확인되기 전까지 알림 수준으로 둔다.",
      "source": "https://attack.mitre.org/techniques/T1190/",
      "weaknessSource": null
    },
    {
      "name": "mid_level_web_request",
      "technique": "T1190",
      "weakness": null,
      "condition": "요청 주소(data.url)가 있는 경보의 Wazuh 규칙 수준(rule.level)이 4 이상 9 이하라서 한 번짜리 의심 이벤트로 분류되었지만, 주입 표기나 반복 기준을 채우지는 못했다. 수업 단어만 있는 요청과 평소보다 긴 주소가 여기에 든다. 막지 않고 알림만 한다.",
      "fields": [
        "rule.level",
        "data.url",
        "data.count"
      ],
      "thresholds": {
        "levelMin": 4,
        "levelMax": 9
      },
      "alertOnly": true,
      "evidence": "T1190의 감지 지침은 공개 엔드포인트로 오는 비정상 요청과 의심스러운 URL·매개변수 구조를 살피라고 하고, Wazuh 규칙 수준 5~9는 오류·낮은 관련성 공격·처음 본 이벤트 같은 한 번짜리 의심 이벤트(10부터가 여러 번의 오류)라서 반복이 확인되기 전까지 알림으로 남긴다.",
      "source": "https://attack.mitre.org/techniques/T1190/",
      "weaknessSource": null
    }
  ];
// PATTERNS-END

const byName = (name) => PATTERNS.find((pattern) => pattern.name === name);
const SQL = byName('sql_injection_repeated');
const SCRIPT = byName('script_injection_repeated');
const PATH = byName('path_traversal_repeated');
const COMMAND = byName('command_separator_repeated');
const SINGLE = byName('single_injection_like_attempt');
const LEVELED = byName('mid_level_web_request');
const REPEATED = [
  { kind: 'sql', pattern: SQL },
  { kind: 'script', pattern: SCRIPT },
  { kind: 'path', pattern: PATH },
  { kind: 'command', pattern: COMMAND },
];

// 확신도 = 경보가 패턴과 얼마나 뚜렷하게 맞는지(0~1). 행동은 확신도로만 정합니다.
const BLOCK_AT = 0.85; // 이 값 이상이면 block
const ALERT_AT = 0.5; // 이 값 이상이면 alert, 그 아래는 record
const STRONG_CAP = 0.95; // 기준의 두 배 이상이면 가장 뚜렷함
const ALERT_ONLY_CAP = 0.8; // 알림만 하는 패턴이나 막을 주소가 올바르지 않은 경우의 상한(0.85 미만)
const MAX_COUNT = 1_000_000;
const MAX_URL = 2000;

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/u;
const IPV6 = /^[0-9a-f:]{2,39}$/iu;
const isAddress = (value) => typeof value === 'string'
  && (IPV4.test(value) || (value.includes(':') && IPV6.test(value) && value.split(':').length <= 8));
const round2 = (number) => Math.round(number * 100) / 100;

// 요청 주소에서 주입 형태를 찾습니다. 수업 경보의 문서용 표식(doc-sql-… 등)과 실제 공격 모양을 둘 다 봅니다.
// 'select-course', 'script-class', 'up-notes' 같은 평범한 단어만으로는 맞지 않도록 연산자·꺾쇠·점 두 개 같은 모양을 요구합니다.
const SHAPES = {
  sql: [/\bdoc-sql/u, /\bunion\s+(?:all\s+)?select\b/u, /['"]\s*(?:or|and)\s+['"\d]/u, /;\s*(?:drop|delete|insert|update)\s/u, /\bselect\b[^&]*\bfrom\b/u],
  script: [/\bdoc-script/u, /<\s*script/u, /javascript\s*:/u, /\bon(?:error|load|click|mouseover)\s*=/u],
  path: [/\bdoc-up\b/u, /\.\.[/\\]/u],
  command: [/\bdoc-cmd/u, /[;|&`]\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh)\b/u, /\$\(/u],
};
// 표식 하나가 SQL과 스크립트를 함께 뜻하는 경우입니다.
const MIXED = /\bdoc-mixed/u;
// 설명에 이 말이 있으면 주입처럼 보이는 표기가 한 번 있었다는 뜻으로 읽습니다(부정문에 쓰이는 말은 넣지 않았습니다).
const WEAK_CUE = /따옴표|구분 문자|이상한 검색|주입처럼 보이는 표기/u;

function decodedUrl(value) {
  if (typeof value !== 'string' || value.length > MAX_URL) return null;
  let text = value;
  for (let round = 0; round < 2; round += 1) {
    try { text = decodeURIComponent(text); } catch { break; }
  }
  return text.toLowerCase();
}

function kindsIn(url) {
  const kinds = new Set();
  for (const [kind, shapes] of Object.entries(SHAPES)) if (shapes.some((shape) => shape.test(url))) kinds.add(kind);
  if (MIXED.test(url)) { kinds.add('sql'); kinds.add('script'); }
  return kinds;
}

// 건수가 없으면 요청 한 번으로 봅니다. 숫자가 아니거나 음수·소수·너무 크면 읽을 수 없는 경보입니다.
function repeatCount(value) {
  if (value === undefined || value === null || value === '') return 1;
  const number = typeof value === 'number' ? value : (typeof value === 'string' && /^\d{1,7}$/u.test(value.trim()) ? Number(value) : NaN);
  return Number.isInteger(number) && number >= 0 && number <= MAX_COUNT ? number : null;
}

// Wazuh 규칙 수준이 한 번짜리 의심 이벤트 구간(기본 4~9)인지 봅니다. 숫자나 숫자 문자열만 받습니다.
function inLevelBand(value) {
  const level = typeof value === 'number' ? value : (typeof value === 'string' && /^\d{1,2}$/u.test(value.trim()) ? Number(value) : NaN);
  return Number.isInteger(level) && level >= LEVELED.thresholds.levelMin && level <= LEVELED.thresholds.levelMax;
}

// 1건부터 0.5, 기준 직전까지 0.84 아래, 기준에서 0.85, 기준의 두 배에서 0.95.
function strength(value, limit) {
  if (value < 1) return 0;
  if (value < limit) return round2(ALERT_AT + (BLOCK_AT - ALERT_AT - 0.01) * ((value - 1) / (limit - 1)));
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
  const count = repeatCount(data.count);
  const url = decodedUrl(data.url);
  if (count === null || (data.url !== undefined && data.url !== null && url === null)) {
    return result(0, '맞는 패턴 없음: 반복 건수나 요청 주소를 읽을 수 없어 기록만 합니다.');
  }
  const kinds = url ? kindsIn(url) : new Set();
  const description = typeof alert.rule?.description === 'string' ? alert.rule.description : '';

  const matches = [];
  for (const { kind, pattern } of REPEATED) {
    if (!kinds.has(kind)) continue;
    const limit = pattern.thresholds.repeats;
    if (count >= limit) {
      const score = strength(count, limit);
      matches.push({ pattern, score: pattern.alertOnly ? Math.min(score, ALERT_ONLY_CAP) : score });
    }
  }
  if (!matches.length) {
    // 반복 기준에 못 미치는 주입 형태, 또는 설명이 한 번뿐인 의심 표기를 말하는 경우: 알림만.
    if (kinds.size && count >= 1) matches.push({ pattern: SINGLE, score: Math.min(strength(count, SQL.thresholds.repeats), ALERT_ONLY_CAP) });
    else if (WEAK_CUE.test(description)) matches.push({ pattern: SINGLE, score: ALERT_AT });
    // 주입 표기가 없어도 Wazuh 가 한 번짜리 의심 이벤트(수준 4~9)로 분류한 웹 요청은 알림으로 남깁니다.
    else if (inLevelBand(alert.rule?.level) && typeof data.url === 'string') matches.push({ pattern: LEVELED, score: ALERT_AT });
  }
  if (!matches.length) return result(0, '맞는 패턴 없음: 주입 형태가 없어 기록만 합니다.');

  matches.sort((a, b) => b.score - a.score);
  let confidence = matches[0].score;
  const names = matches.map((match) => match.pattern.name);
  let note;
  if (confidence >= BLOCK_AT && !isAddress(data.srcip)) {
    confidence = Math.min(confidence, ALERT_ONLY_CAP);
    note = ' 막을 주소가 올바르지 않아 막지 않고 사람이 확인합니다.';
  } else if (confidence >= BLOCK_AT) {
    note = ' 같은 주소에서 반복된 명확한 주입 시도라 막습니다.';
  } else if (matches[0].pattern.alertOnly) {
    note = ' 이 수업에서는 막지 않고 알림만 합니다.';
  } else {
    note = ' 막을 만큼 명확하지 않아 알립니다.';
  }
  return result(confidence, `${names.join(' + ')}:${note}`);
}
