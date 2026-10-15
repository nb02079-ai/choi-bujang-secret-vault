// 외부 전송(자료 빼돌리기) 경보를 block / alert / record로 나눕니다.
// 이 파일은 혼자 계산합니다: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않습니다.
// 경보 원본은 고치지 않습니다. 같은 경보에는 항상 같은 답을 냅니다(저장된 상태 없음).
// 판정기 규칙을 대신하지 않고, 확인 단계 하나로 불러 쓰는 부품입니다.
//
// 막는 것은 큰 전송(data.bytes 가 기준 이상)이 처음 보는 목적지·업무 시간 밖·반복·명령 통로·자료실 전체 복사 같은 뚜렷한 표현과 함께 확인되고, 막을 목적지 주소가 올바른 경우뿐입니다.
// 전송량이 작은 전송·실패한 전송·평소 목적지로의 변화 같은 애매한 경보와 Wazuh 규칙 수준 4~9의 한 번짜리 의심 경보는 알림까지만 합니다. 수준 3 이하는 기록만 합니다.
// 계정(srcuser)과 파일 수(data.files)는 출처에 근거가 없어 확신도에 쓰지 않습니다.

// 패턴 목록: xdr/exfiltration/patterns.json 과 같은 내용입니다(시험이 두 곳이 같은지 비교합니다).
// 근거는 MITRE ATT&CK T1041(보조 T1048)이고, 큰 전송의 기준·문구의 모양·점수는 이 수업의 학생 기준(로컬 추정)입니다.
// PATTERNS-BEGIN
const PATTERNS_FILE = {
  "version": 1,
  "basis": {
    "technique": "T1041",
    "name": "Exfiltration Over C2 Channel",
    "url": "https://attack.mitre.org/techniques/T1041/",
    "relatedTechniques": [
      "T1048"
    ],
    "checkedAt": "2026-10-15",
    "checked": [
      "https://attack.mitre.org/techniques/T1041/ (이미 쓰는 명령 통로로 자료를 내보냄, 탐지는 파일·자료 접근 직후의 이상한 외부 전송량과 드문 외부 목적지, 사용자 지정 포트를 본다)",
      "https://attack.mitre.org/techniques/T1048/ (명령 통로와 다른 프로토콜·다른 위치로 내보냄, 탐지는 평소와 다른 파일 전송, 업무 시간 밖 활동, 평소보다 매우 큰 전송량, 외부 끝점으로의 파일 이동을 본다)"
    ],
    "notChecked": "두 페이지는 읽기 도구가 만든 요약으로 확인했고 원문 전체를 직접 읽지는 못했습니다. T1041 페이지는 앞부분 100000자까지만 읽었고 뒤 28463자는 읽지 못했습니다. T1048 요약에는 평소 쓰지 않는 포트가 나오지 않았습니다(포트는 T1041 쪽 요약에만 나옵니다). 큰 전송의 바이트 기준과 반복 횟수의 뜻은 출처에 없는 로컬 추정입니다.",
    "note": "경보에는 목적지·전송 크기를 나타내는 구조화된 칸 가운데 data.dstip, data.bytes, data.files, data.count 가 있습니다. 값은 문자열이므로 숫자로 바꿔 읽습니다. '처음 보는 목적지', '업무 시간 밖', '압축 파일', '명령 통로' 같은 판단은 설명 문구(rule.description)에서 읽습니다. 큰 전송의 기준(thresholds.largeBytes)과 문구의 모양, 점수는 수업용 경보 묶음을 보고 정한 이 수업의 학생 기준입니다. T1030(전송 크기 제한)은 확인하지 않았고 쓰지 않았습니다."
  },
  "thresholds": {
    "largeBytes": 50000000,
    "evidence": "출처에 구체적 숫자가 없어 수업용 경보 묶음에서 공격으로 보이는 전송(7천만 바이트 이상)과 애매한 전송(1천5백만 바이트 이하)을 가르도록 정한 로컬 추정이다."
  },
  "patterns": [
    {
      "name": "large_transfer_to_unfamiliar_destination",
      "technique": "T1041",
      "condition": "설명에 처음 보는 목적지나 처음 보는 주소로 나갔다는 말이 있고, 전송량(data.bytes)이 큰 전송 기준 이상이다. 전송이 실패했거나 전송량이 기준 아래인 경우, 평소 목적지로 나간 경우는 맞지 않는다.",
      "fields": [
        "rule.description",
        "data.bytes",
        "data.dstip",
        "data.srcuser"
      ],
      "alertOnly": false,
      "evidence": "T1041은 외부 전송량이 평소와 어긋나는 것과 드문 외부 목적지로의 세션을 탐지 신호로 설명하고, T1048은 평소보다 매우 큰 전송량과 외부 끝점으로의 파일 이동을 설명한다.",
      "source": "https://attack.mitre.org/techniques/T1041/"
    },
    {
      "name": "off_hours_large_transfer",
      "technique": "T1048",
      "condition": "수업 시간 밖이나 업무 시간 밖에 자료가 외부로 전송됐고(압축 파일이면 더 뚜렷하다), 전송량이 큰 전송 기준 이상이다. 수업 시간 안의 압축 파일 생성이나 읽기는 맞지 않는다.",
      "fields": [
        "rule.description",
        "data.bytes",
        "data.dstip",
        "data.srcuser"
      ],
      "alertOnly": false,
      "evidence": "T1048의 탐지는 업무 시간 밖 활동과 평소보다 큰 전송량이 겹치는 파일 전송을 본다고 설명한다(압축 파일이라는 모양은 로컬 추정).",
      "source": "https://attack.mitre.org/techniques/T1048/"
    },
    {
      "name": "repeated_large_transfer_same_destination",
      "technique": "T1048",
      "condition": "같은 목적지로 대용량 전송이 여러 번 반복됐다고 설명하고, 전송량이 큰 전송 기준 이상이다. 작은 전송이 반복된 경우는 맞지 않는다.",
      "fields": [
        "rule.description",
        "data.bytes",
        "data.count",
        "data.dstip"
      ],
      "alertOnly": false,
      "evidence": "T1048의 탐지는 평소보다 매우 큰 전송량의 파일 전송을, T1041은 외부 전송량의 이상을 본다고 설명한다(같은 목적지로의 반복이라는 모양은 로컬 추정).",
      "source": "https://attack.mitre.org/techniques/T1048/"
    },
    {
      "name": "command_channel_or_unusual_port_transfer",
      "technique": "T1041",
      "condition": "설명에 명령 통로로 보냈거나 평소 쓰지 않던 포트로 자료가 전송됐다는 말이 있고, 전송량이 큰 전송 기준 이상이다. 명령 통로에 짧은 자료 이름만 보였거나 전송량이 작은 경우는 맞지 않는다.",
      "fields": [
        "rule.description",
        "data.bytes",
        "data.dstip"
      ],
      "alertOnly": false,
      "evidence": "T1041은 공격자가 자료를 명령 통로와 같은 프로토콜에 실어 내보낸다고 설명하고, 탐지에서 사용자 지정 TCP/UDP 포트를 통한 이상한 외부 전송량을 본다.",
      "source": "https://attack.mitre.org/techniques/T1041/"
    },
    {
      "name": "bulk_copy_to_external",
      "technique": "T1048",
      "condition": "설명에 자료실 전체나 자료 묶음이 외부 주소로 복사됐다는 말이 있고, 전송량이 큰 전송 기준 이상이다. 내부 주소로의 읽기나 동기화는 맞지 않는다.",
      "fields": [
        "rule.description",
        "data.bytes",
        "data.files",
        "data.dstip"
      ],
      "alertOnly": false,
      "evidence": "T1048의 탐지는 외부 끝점으로의 파일 이동과 평소보다 매우 큰 전송량을 본다고 설명한다('자료실 전체'라는 문구의 모양은 로컬 추정).",
      "source": "https://attack.mitre.org/techniques/T1048/"
    }
  ],
  "notExfiltration": {
    "condition": "내부 주소나 수업 자료 주소로의 읽기·저장·동기화, 작은 전송량의 읽기, 새로고침·세션 확인·로그아웃, 전송이 실패해 나간 자료가 없는 경우, 큰 전송 기준 아래의 처음 보는 주소 전송, 수업 시간 안의 압축 파일 생성은 자료 빼돌리기로 보지 않는다.",
    "evidence": "출처가 말하는 유출은 평소와 다른 목적지나 시각으로 평소보다 큰 자료가 실제로 나가는 것이므로, 일상적인 내부 읽기나 나간 자료가 없는 경우는 해당하지 않는다."
  }
};
// PATTERNS-END

const PATTERNS = PATTERNS_FILE.patterns;
const byName = (name) => PATTERNS.find((pattern) => pattern.name === name);
const UNFAMILIAR = byName('large_transfer_to_unfamiliar_destination');
const OFF_HOURS = byName('off_hours_large_transfer');
const REPEATED = byName('repeated_large_transfer_same_destination');
const CHANNEL = byName('command_channel_or_unusual_port_transfer');
const BULK = byName('bulk_copy_to_external');
const LARGE_BYTES = PATTERNS_FILE.thresholds.largeBytes;

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
// '외부 전송은 아직 없습니다' 같은 부정 표현은 먼저 걷어냅니다.
const NEGATED = /(?:외부 |파일 )?전송(?:은|이)?\s*(?:아직 )?없습니다/gu;
const NEW_DESTINATION = /처음 보는 (?:목적지|주소)/u;
const OFF_TIME = /(?:수업|업무) 시간 밖/u;
const SENT = /나갔|전송|올라갔|복사/u;
const REPEAT = /반복|전송이\s*\d+번/u;
const COMMAND_CHANNEL = /명령 통로|쓰지 않(?:던|는) 포트/u;
const BULK_COPY = /(?:자료실|자료) 전체[^.]{0,20}외부/u;
const FAILED = /실패/u;

const round2 = (value) => Math.round(value * 100) / 100;

// 올바른 목적지 주소만 막을 수 있습니다: IPv4 한 개 또는 IPv6 한 개.
function isAddress(value) {
  if (typeof value !== 'string') return false;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u.exec(value);
  if (v4) return v4.slice(1).every((part) => Number(part) <= 255);
  return value.length <= 45 && value.includes(':') && /^[0-9a-f:]+$/iu.test(value);
}

// 전송량: 숫자 또는 숫자로만 된 문자열. 읽을 수 없으면 null.
function readBytes(value) {
  if (typeof value === 'number') return Number.isFinite(value) && value >= 0 ? value : null;
  if (typeof value === 'string' && /^\d{1,15}$/u.test(value.trim())) return Number(value);
  return null;
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
  const bytes = readBytes(data.bytes);
  const large = bytes !== null && bytes >= LARGE_BYTES;
  const failed = FAILED.test(description);

  const names = [];
  if (large && !failed) {
    if (NEW_DESTINATION.test(description)) names.push(UNFAMILIAR.name);
    if (OFF_TIME.test(description) && SENT.test(description)) names.push(OFF_HOURS.name);
    if (REPEAT.test(description)) names.push(REPEATED.name);
    if (COMMAND_CHANNEL.test(description)) names.push(CHANNEL.name);
    if (BULK_COPY.test(description)) names.push(BULK.name);
  }

  let confidence;
  let note;
  if (names.length) {
    confidence = names.length > 2 ? MANY_PATTERNS : names.length > 1 ? TWO_PATTERNS : ONE_PATTERN;
    if (!isAddress(data.dstip)) {
      confidence = Math.min(confidence, ALERT_ONLY_CAP);
      note = ' 막을 목적지 주소가 올바르지 않아 막지 않고 사람이 확인합니다.';
    } else {
      note = ' 평소와 다른 큰 외부 전송의 뚜렷한 표현이 있어 막습니다.';
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
    return result(0, '맞는 패턴 없음: 평소와 다른 큰 외부 전송의 흔적이 없어 기록만 합니다.');
  }
  return result(confidence, `${names.join(' + ')}:${note}`);
}
