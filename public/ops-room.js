// 탈환 작전실 화면의 표시 규칙입니다. 서버(/api/ops/summary)가 이번에 돌려준 응답만 읽어 화면에 보일 내용을 만듭니다.
// 화면이 스스로 성공 문구를 만들지 않습니다. 서버가 읽었다고 알린 구역만 '확인됨'이고, 읽지 못한 구역은 '미확인',
// 서버가 기록을 남기지 않는다고 알린 항목과 심판이 확인하는 항목은 '미기록'·'미실행'으로 따로 보입니다.
// 가상 메모의 제목과 내용은 서버가 보내지 않으며, 이 모듈도 그런 항목을 읽지 않습니다. 모든 값은 글자로만 쓰입니다.

export const OPS_SCHEMA = 'vault.ops.summary.v1';
export const OPS_NOTE = '이 화면은 서버가 이번에 돌려준 응답만 보여 줍니다. 화면의 문구는 통과 근거가 아니며 판정은 심판이 합니다. 가상 메모의 제목과 내용은 표시하지 않습니다.';

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const count = (value) => (Number.isInteger(value) && value >= 0 && value <= 1_000_000 ? String(value) : '-');
const ref = (value) => (typeof value === 'string' && /^[0-9a-f]{8}$/u.test(value) ? value : '-');
const hash = (value) => (typeof value === 'string' && /^[0-9a-f]{12}$/u.test(value) ? value : '-');
const word = (value) => (typeof value === 'string' && /^[a-z_]{1,20}$/u.test(value) ? value : '-');
const note = (value) => (typeof value === 'string' ? value.slice(0, 200) : '');
const when = (value) => (typeof value === 'string' && Number.isFinite(Date.parse(value)) ? `${new Date(value).toISOString().slice(0, 19).replace('T', ' ')} UTC` : '시각 미상');
const tagOf = (section) => (isObject(section) && section.confirmed === true ? '확인됨' : '미확인');
const list = (value) => (Array.isArray(value) ? value.slice(0, 10) : []);

const STATE_LABELS = { pending: '승인 대기', expired: '대기 만료', approved: '승인됨', denied: '거부됨', revoked: '폐기됨', other: '기타' };
const missing = (title, id) => ({ id, title, tag: '미확인', lines: ['서버 응답에서 이 구역을 읽지 못했습니다.'], records: [] });

function deciderCard(section) {
  if (!isObject(section)) return missing('판정기 규칙', 'decider');
  const lines = [];
  if (section.confirmed === true) {
    const names = list(section.ruleIds).filter((name) => typeof name === 'string' && /^[a-z_]{1,40}$/u.test(name));
    lines.push(`규칙 ${count(section.ruleCount)}개: ${names.join(', ') || '-'}`);
    lines.push(`구역 경로 ${count(section.zoneRouteCount)}개, 허용 경로 ${count(section.allowedRouteCount)}개`);
    lines.push(`정책 지문: ${hash(section.policyDigest)}`);
  } else lines.push('규칙 정의를 읽지 못했습니다.');
  const results = isObject(section.results) ? section.results : {};
  lines.push(`판정 결과 집계: ${results.recorded === true ? '기록됨' : '미기록'}${note(results.reason) ? ` (${note(results.reason)})` : ''}`);
  return { id: 'decider', title: '판정기 규칙', tag: tagOf(section), lines, records: [] };
}

function detectionCard(section) {
  if (!isObject(section)) return missing('탐지 사건', 'detection');
  const lines = [];
  const rule = isObject(section.rule) ? section.rule : {};
  if (section.confirmed === true) {
    lines.push(`탐지 기준: ${count(rule.windowSeconds)}초 안에 GET ${count(rule.threshold)}건 초과, 이유 코드 ${word(rule.reasonCode)}`);
  } else lines.push('탐지 기준을 읽지 못했습니다.');
  const events = isObject(section.events) ? section.events : {};
  lines.push(`탐지 사건: ${events.recorded === true ? '기록됨' : '미기록'}${note(events.reason) ? ` (${note(events.reason)})` : ''}`);
  return { id: 'detection', title: '탐지 사건', tag: tagOf(section), lines, records: [] };
}

function revocationCard(section) {
  if (!isObject(section)) return missing('회수 상태', 'revocation');
  const lines = [];
  const records = [];
  if (section.confirmed === true) {
    const counts = isObject(section.counts) ? section.counts : {};
    lines.push(`내 기기 ${count(section.total)}개${section.truncated === true ? ' 이상(일부만 읽음)' : ''}`);
    lines.push(Object.keys(STATE_LABELS).map((key) => `${STATE_LABELS[key]} ${count(counts[key])}`).join(', '));
    for (const item of list(section.records)) {
      if (!isObject(item)) continue;
      records.push(`기기 ${ref(item.ref)} · ${STATE_LABELS[item.status] ?? '기타'} · 요청 ${when(item.createdAt)}${item.decidedAt ? ` · 결정 ${when(item.decidedAt)}` : ''}`);
    }
  } else lines.push('기기 승인 기록을 읽지 못했습니다.');
  const enforcement = isObject(section.enforcement) ? section.enforcement : {};
  lines.push(`실제 회수 집행: ${enforcement.run === true ? '실행됨' : '미실행'}${note(enforcement.reason) ? ` (${note(enforcement.reason)})` : ''}`);
  return { id: 'revocation', title: '회수 상태', tag: tagOf(section), lines, records };
}

function recoveryCard(section) {
  if (!isObject(section)) return missing('복구 버전', 'recovery');
  const lines = [];
  const records = [];
  const backups = isObject(section.backups) ? section.backups : {};
  const restores = isObject(section.restores) ? section.restores : {};
  lines.push(backups.confirmed === true ? `사본 ${count(backups.total)}건${backups.truncated === true ? ' 이상' : ''}` : '사본 기록을 읽지 못했습니다.');
  lines.push(restores.confirmed === true ? `복원 기록 ${count(restores.total)}건${restores.truncated === true ? ' 이상' : ''}` : '복원 기록을 읽지 못했습니다.');
  if (backups.confirmed === true) {
    for (const item of list(backups.records)) {
      if (isObject(item)) records.push(`사본 메모 ${ref(item.ref)} · 해시 ${hash(item.hash12)} · ${when(item.at)}`);
    }
  }
  if (restores.confirmed === true) {
    for (const item of list(restores.records)) {
      if (isObject(item)) records.push(`복원 메모 ${ref(item.ref)} · 해시 ${hash(item.hash12)} · ${word(item.outcome)} · ${when(item.at)}`);
    }
  }
  const snapshot = isObject(section.policySnapshot) ? section.policySnapshot : {};
  lines.push(`정책 사본 버전: ${snapshot.confirmed === true ? '확인됨' : '미확인'}${note(snapshot.reason) ? ` (${note(snapshot.reason)})` : ''}`);
  return { id: 'recovery', title: '복구 버전', tag: tagOf(section), lines, records };
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
