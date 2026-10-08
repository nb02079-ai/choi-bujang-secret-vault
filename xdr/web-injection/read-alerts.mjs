// 확인용 읽기 모듈입니다. decide.mjs는 이 파일을 불러오지 않고, 이 파일도 decide.mjs를 부르지 않습니다.
// 웹 접근 경보 묶음에서 시각·출발 주소·계정·규칙 수준·설명만 뽑아 한 경보당 한 줄로 보여 줍니다.
// 계정은 정상 이벤트에만 있고 공격 경보에는 없을 수 있어, 없는 값은 '-'로 채웁니다.
// 원본 경보는 읽기만 하고 고치지 않으며, 비밀값처럼 보이는 문자열은 [가림]으로 바꿔 출력합니다.
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const FIXTURE = fileURLToPath(new URL('../fixtures/web-injection.json', import.meta.url));
const MASK = '[가림]';
const MAX_TEXT = 200;
const SECRET = new RegExp([
  String.raw`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`,
  String.raw`\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`,
  String.raw`\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{6,}`,
  String.raw`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}`,
  String.raw`\bsk-[A-Za-z0-9_-]{16,}`,
  String.raw`\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey)\s*[=:]\s*\S+`,
  String.raw`[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
].join('|'), 'giu');
// 설명이나 계정 칸에 쿼리 모양의 문자열이 섞여 들어와도, 값이 비밀일 수 있는 이름(access_token, key, sig, session 등)은 값을 통째로 가립니다.
const SECRET_PARAM = /([?&;](?:[A-Za-z0-9_.-]*(?:token|key|secret|passw(?:or)?d|pwd|auth|sig|session|sid|jwt|credential|code)[A-Za-z0-9_.-]*)=)[^&#\s]*/giu;

function clean(value) {
  if (typeof value === 'number' && Number.isFinite(value)) value = String(value);
  if (typeof value !== 'string') return null;
  const oneLine = value.replace(/\s+/gu, ' ').trim().replace(SECRET_PARAM, `$1${MASK}`).replace(SECRET, MASK);
  if (!oneLine) return null;
  return oneLine.length > MAX_TEXT ? `${oneLine.slice(0, MAX_TEXT)}…` : oneLine;
}

export function extract(alert) {
  return {
    timestamp: clean(alert?.timestamp),
    srcip: clean(alert?.data?.srcip),
    srcuser: clean(alert?.data?.srcuser),
    level: clean(alert?.rule?.level),
    description: clean(alert?.rule?.description),
  };
}

export const formatRow = (row) => [row.timestamp, row.srcip, row.srcuser, row.level, row.description]
  .map((part) => part ?? '-').join(' | ');

// 경보 하나당 정확히 한 줄을 돌려줍니다. 필드가 없는 경보도 건너뛰지 않고 '-'로 채워 건수가 어긋나지 않게 합니다.
export async function readAlerts(file = FIXTURE) {
  const fixture = JSON.parse(await readFile(file, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'web-injection' || !Array.isArray(fixture.alerts)) {
    throw new Error('web-injection 경보 묶음 형식이 아닙니다.');
  }
  const rows = fixture.alerts.map(extract);
  if (rows.length !== fixture.alerts.length) throw new Error('경보 건수와 뽑은 줄 수가 다릅니다.');
  return { alerts: fixture.alerts.length, rows, lines: rows.map(formatRow) };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const { alerts, rows, lines } = await readAlerts();
    process.stdout.write(`${lines.join('\n')}\n경보 ${alerts}건, 뽑은 줄 ${rows.length}건${alerts === rows.length ? ' (일치)' : ' (불일치)'}\n`);
    if (alerts !== rows.length) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`경보를 읽지 못했습니다: ${error.message}\n`);
    process.exitCode = 1;
  }
}
