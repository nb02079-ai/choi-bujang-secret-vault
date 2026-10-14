// 탈환 작전실 화면의 표시 규칙입니다. 서버(/api/ops/summary)가 이번에 돌려준 응답만 읽어 화면에 보일 내용을 만듭니다.
// 화면이 스스로 성공 문구나 수치를 만들지 않습니다. 표시는 네 가지로 구분합니다.
//   확인됨: 서버가 이번 응답에서 기록을 읽었고, 총수와 상태별 수가 함께 온 가린 기록 목록과 맞는 구역
//   정의:   코드에서 읽은 규칙 이름과 탐지 기준입니다. 판정이나 탐지의 결과가 아닙니다.
//   미확인: 서버가 읽지 못했거나 응답의 수치와 가린 기록이 맞지 않아 숫자를 보이지 않는 구역
//   미기록·미실행: 기록이 남지 않거나 심판이 확인하는 항목
// 화면의 수치는 가린 기록 줄 수와 항상 같아야 합니다. 서버가 보낸 총수·상태별 수가 목록과 다르면 숫자를 보이지 않습니다.
// 가상 메모의 제목과 내용은 서버가 보내지 않으며, 이 모듈도 그런 항목을 읽지 않습니다. 모든 값은 글자로만 쓰입니다.

export const OPS_SCHEMA = 'vault.ops.summary.v1';
export const OPS_NOTE = '이 화면은 서버가 이번에 돌려준 응답만 보여 줍니다. 화면의 문구는 통과 근거가 아니며 판정은 심판이 합니다. 가상 메모의 제목과 내용은 표시하지 않습니다.';
export const MAX_RECORDS = 100;

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const count = (value) => (Number.isInteger(value) && value >= 0 && value <= 1_000_000 ? String(value) : '-');
const ref = (value) => (typeof value === 'string' && /^[0-9a-f]{8}$/u.test(value) ? value : '-');
const hash = (value) => (typeof value === 'string' && /^[0-9a-f]{12}$/u.test(value) ? value : '-');
const word = (value) => (typeof value === 'string' && /^[a-z_]{1,20}$/u.test(value) ? value : '-');
const note = (value) => (typeof value === 'string' ? value.slice(0, 200) : '');
const when = (value) => (typeof value === 'string' && Number.isFinite(Date.parse(value)) ? `${new Date(value).toISOString().slice(0, 19).replace('T', ' ')} UTC` : '시각 미상');
const list = (value) => (Array.isArray(value) ? value.slice(0, MAX_RECORDS) : []);

const STATE_KEYS = ['pending', 'approved', 'denied', 'revoked', 'other'];
const STATE_LABELS = { pending: '승인 대기', approved: '승인됨', denied: '거부됨', revoked: '폐기됨', other: '기타' };
const missing = (title, id) => ({ id, title, tag: '미확인', lines: ['서버 응답에서 이 구역을 읽지 못했습니다.'], records: [] });
const MISMATCH = '서버 응답의 수치와 가린 기록이 맞지 않아 수치를 표시하지 않습니다.';

// 총수는 목록 길이와 같아야 하고, 상한을 넘으면 truncated가 true여야 합니다.
const listConsistent = (section) => isObject(section) && section.confirmed === true && Array.isArray(section.records)
  && section.records.length <= MAX_RECORDS && Number.isInteger(section.total) && section.total === section.records.length
  && section.records.every(isObject) && typeof section.truncated === 'boolean';

function countsConsistent(section) {
  if (!listConsistent(section) || !isObject(section.counts)) return false;
  const tally = Object.fromEntries(STATE_KEYS.map((key) => [key, 0]));
  for (const record of section.records) {
    if (!STATE_KEYS.includes(record.status)) return false;
    tally[record.status] += 1;
  }
  return STATE_KEYS.every((key) => section.counts[key] === tally[key]);
}

const more = (section) => (section.truncated === true ? ' 이상(읽기 한도 100건까지만 표시)' : '');

function deciderCard(section) {
  if (!isObject(section) || section.kind !== 'definition') return missing('판정기 규칙', 'decider');
  const names = list(section.ruleIds).filter((name) => typeof name === 'string' && /^[a-z_]{1,40}$/u.test(name));
  const results = isObject(section.results) ? section.results : {};
  return { id: 'decider', title: '판정기 규칙', tag: '정의', records: [], lines: [
    `규칙 이름(코드의 정의, 판정 결과가 아님): ${names.join(', ') || '-'}`,
    `판정 결과 집계: ${results.recorded === true ? '기록됨' : '미기록'}${note(results.reason) ? ` (${note(results.reason)})` : ''}`,
  ] };
}

function detectionCard(section) {
  if (!isObject(section) || section.kind !== 'definition') return missing('탐지 사건', 'detection');
  const rule = isObject(section.rule) ? section.rule : {};
  const events = isObject(section.events) ? section.events : {};
  return { id: 'detection', title: '탐지 사건', tag: '정의', records: [], lines: [
    `탐지 기준(코드의 정의, 사건이 아님): ${count(rule.windowSeconds)}초 안에 GET ${count(rule.threshold)}건 초과, 이유 코드 ${word(rule.reasonCode)}`,
    `탐지 사건: ${events.recorded === true ? '기록됨' : '미기록'}${note(events.reason) ? ` (${note(events.reason)})` : ''}`,
  ] };
}

function revocationCard(section) {
  if (!isObject(section)) return missing('회수 상태', 'revocation');
  const enforcement = isObject(section.enforcement) ? section.enforcement : {};
  const tail = `실제 회수 집행: ${enforcement.run === true ? '실행됨' : '미실행'}${note(enforcement.reason) ? ` (${note(enforcement.reason)})` : ''}`;
  if (section.confirmed !== true) return { id: 'revocation', title: '회수 상태', tag: '미확인', records: [], lines: ['기기 승인 기록을 읽지 못했습니다.', tail] };
  if (!countsConsistent(section)) return { id: 'revocation', title: '회수 상태', tag: '미확인', records: [], lines: [MISMATCH, tail] };
  const counts = section.counts;
  const records = section.records.map((item) => `기기 ${ref(item.ref)} · ${STATE_LABELS[item.status]} · 요청 ${when(item.createdAt)}`
    + `${item.decidedAt ? ` · 결정 ${when(item.decidedAt)}` : ''}${item.status === 'pending' && item.expiresAt ? ` · 만료 예정 ${when(item.expiresAt)}` : ''}`);
  return { id: 'revocation', title: '회수 상태', tag: '확인됨', records, lines: [
    `내 기기 ${count(section.records.length)}개${more(section)}`,
    STATE_KEYS.map((key) => `${STATE_LABELS[key]} ${count(counts[key])}`).join(', '),
    tail,
  ] };
}

function recoveryCard(section) {
  if (!isObject(section)) return missing('복구 버전', 'recovery');
  const backups = isObject(section.backups) ? section.backups : {};
  const restores = isObject(section.restores) ? section.restores : {};
  const snapshot = isObject(section.policySnapshot) ? section.policySnapshot : {};
  const lines = [];
  const records = [];
  let confirmed = false;
  let mismatch = false;
  if (backups.confirmed !== true) lines.push('사본 기록을 읽지 못했습니다.');
  else if (!listConsistent(backups)) { mismatch = true; lines.push(`사본: ${MISMATCH}`); } else {
    confirmed = true;
    lines.push(`사본 ${count(backups.records.length)}건${more(backups)}`);
    for (const item of backups.records) records.push(`사본 메모 ${ref(item.ref)} · 해시 ${hash(item.hash12)} · ${when(item.at)}`);
  }
  if (restores.confirmed !== true) lines.push('복원 기록을 읽지 못했습니다.');
  else if (!listConsistent(restores)) { mismatch = true; lines.push(`복원: ${MISMATCH}`); } else {
    confirmed = true;
    lines.push(`복원 기록 ${count(restores.records.length)}건${more(restores)}`);
    for (const item of restores.records) records.push(`복원 메모 ${ref(item.ref)} · 해시 ${hash(item.hash12)} · ${word(item.outcome)} · ${when(item.at)}`);
  }
  lines.push(`정책 사본 버전: ${snapshot.confirmed === true ? '확인됨' : '미확인'}${note(snapshot.reason) ? ` (${note(snapshot.reason)})` : ''}`);
  return { id: 'recovery', title: '복구 버전', tag: confirmed && !mismatch ? '확인됨' : '미확인', records, lines };
}

export function buildOpsView(summary) {
  const valid = isObject(summary) && summary.schema === OPS_SCHEMA;
  const source = valid ? summary : {};
  return {
    note: OPS_NOTE,
    readAt: valid && Number.isFinite(Date.parse(summary.readAt)) ? when(summary.readAt) : null,
    cards: [deciderCard(source.decider), detectionCard(source.detection), revocationCard(source.revocation), recoveryCard(source.recovery)],
    notRun: valid ? list(summary.notRun).filter(isObject).map((item) => note(item.text)).filter(Boolean) : [],
  };
}
