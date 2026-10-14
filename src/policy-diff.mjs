// 10단계: 침해 전에 검증한 안전 정책 사본과 현재 시험 정책의 차이만 보여 줍니다.
// 이 모듈은 읽기만 합니다. 파일 쓰기, 네트워크 호출, 정책 변경, 복원을 하지 않습니다.
// 사본이 없거나 검증에 실패하면 비교하지 않고 PolicyCopyError로 중단합니다.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describePolicy } from './decider.mjs';

export const SNAPSHOT_SCHEMA = 'vault.policy.snapshot.v1';
const MAX_SNAPSHOT_BYTES = 256 * 1024;
const CONFIG_URL = new URL('../aleph.config.json', import.meta.url);

export class PolicyCopyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PolicyCopyError';
    this.code = code;
  }
}

const isPlain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const isText = value => typeof value === 'string' && value.length >= 1 && value.length <= 200 && !/[\u0000-\u001f\u007f]/u.test(value);
const isList = value => Array.isArray(value) && value.length <= 200 && value.every(isText);
const mapOf = check => value => isPlain(value) && Object.keys(value).length <= 50
  && Object.entries(value).every(([key, item]) => /^[A-Za-z][A-Za-z0-9_]{0,39}$/u.test(key) && check(item));
// 정책 항목의 이름과 형식입니다. 이 목록에 없는 이름은 사본 검증에서 거부합니다.
const POLICY_SPEC = Object.freeze({
  ruleIds: isList,
  reasonCodes: mapOf(isText),
  zoneRoutes: mapOf(isList),
  writeMethods: isList,
  functionNames: isList,
  stepUp: mapOf(value => Number.isInteger(value) && value >= 0 && value <= 100000),
  trustedSources: isList,
  allowedRoutes: isList,
});

export const canonical = value => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (isPlain(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
};

export const snapshotDigest = ({ version, policy }) => createHash('sha256')
  .update(canonical({ schema: SNAPSHOT_SCHEMA, version, policy })).digest('hex');

export function validatePolicy(policy, code) {
  const names = Object.keys(POLICY_SPEC);
  if (!isPlain(policy) || Object.keys(policy).sort().join() !== [...names].sort().join()
      || !names.every(name => POLICY_SPEC[name](policy[name]))) {
    throw new PolicyCopyError(code, '정책 항목의 이름이나 형식이 맞지 않습니다.');
  }
  return policy;
}

// 현재 시험 정책: 판정기가 내놓는 읽기 전용 복사본에 aleph.config.json의 허용 경로를 더합니다.
export function currentPolicy({ configUrl = CONFIG_URL } = {}) {
  let allowedRoutes;
  try { allowedRoutes = JSON.parse(readFileSync(configUrl, 'utf8')).allowedRoutes; } catch { allowedRoutes = undefined; }
  return validatePolicy({ ...describePolicy(), allowedRoutes }, 'current_policy_invalid');
}

// 사본을 읽어 검증합니다. 기대 지문은 사본 밖에서 받은 값이며 없으면 중단합니다.
export function loadSnapshot(path, expectedSha256) {
  if (typeof expectedSha256 !== 'string' || expectedSha256 === '') {
    throw new PolicyCopyError('expected_missing', '사본 밖에서 받은 기대 지문이 없어 검증할 수 없습니다.');
  }
  if (!/^[0-9a-f]{64}$/u.test(expectedSha256)) {
    throw new PolicyCopyError('expected_format', '기대 지문은 소문자 16진수 64자여야 합니다.');
  }
  let raw;
  try {
    raw = readFileSync(path);
  } catch (error) {
    throw new PolicyCopyError(error?.code === 'ENOENT' ? 'snapshot_missing' : 'snapshot_unreadable',
      error?.code === 'ENOENT' ? '정책 사본이 없습니다.' : '정책 사본을 읽을 수 없습니다.');
  }
  if (raw.length > MAX_SNAPSHOT_BYTES) throw new PolicyCopyError('snapshot_too_large', '정책 사본이 너무 큽니다.');
  let snapshot;
  try { snapshot = JSON.parse(raw.toString('utf8')); } catch { throw new PolicyCopyError('snapshot_not_json', '정책 사본이 JSON 형식이 아닙니다.'); }
  if (!isPlain(snapshot) || Object.keys(snapshot).sort().join() !== 'policy,schema,sha256,version') {
    throw new PolicyCopyError('snapshot_fields', '정책 사본의 항목이 schema, version, policy, sha256과 다릅니다.');
  }
  if (snapshot.schema !== SNAPSHOT_SCHEMA) throw new PolicyCopyError('snapshot_schema', '정책 사본의 schema가 맞지 않습니다.');
  if (typeof snapshot.version !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/u.test(snapshot.version)) {
    throw new PolicyCopyError('snapshot_version', '정책 사본의 version이 없거나 형식이 틀립니다.');
  }
  validatePolicy(snapshot.policy, 'snapshot_policy');
  const digest = snapshotDigest(snapshot);
  if (snapshot.sha256 !== digest) throw new PolicyCopyError('digest_mismatch', '정책 사본의 내용이 기록된 지문과 다릅니다.');
  if (digest !== expectedSha256) throw new PolicyCopyError('expected_mismatch', '정책 사본의 지문이 기대 지문과 다릅니다.');
  return { version: snapshot.version, digest, policy: snapshot.policy };
}

function collect(path, before, after, out) {
  if (Array.isArray(before) && Array.isArray(after)) {
    const had = new Set(before);
    const has = new Set(after);
    const start = out.length;
    for (const item of after) if (!had.has(item)) out.push({ path, kind: 'add', after: item });
    for (const item of before) if (!has.has(item)) out.push({ path, kind: 'remove', before: item });
    if (out.length === start && canonical(before) !== canonical(after)) out.push({ path, kind: 'reorder', before, after });
  } else if (isPlain(before) && isPlain(after)) {
    for (const key of [...new Set([...Object.keys(before), ...Object.keys(after)])].sort()) {
      const child = `${path}.${key}`;
      if (!Object.hasOwn(before, key)) out.push({ path: child, kind: 'add', after: after[key] });
      else if (!Object.hasOwn(after, key)) out.push({ path: child, kind: 'remove', before: before[key] });
      else collect(child, before[key], after[key], out);
    }
  } else if (before !== after) {
    out.push({ path, kind: 'change', before, after });
  }
}

// 복원하면 달라지는 점만 계산합니다. before는 현재 정책, after는 사본(복원 뒤)입니다.
export function diffPolicy(current, restored) {
  const changes = [];
  for (const name of Object.keys(POLICY_SPEC)) collect(name, current[name], restored[name], changes);
  return changes;
}

export function planRestore(path, expectedSha256, options) {
  const snapshot = loadSnapshot(path, expectedSha256);
  const changes = diffPolicy(currentPolicy(options), snapshot.policy);
  const areas = [...new Set(changes.map(change => change.path.split('.')[0]))];
  return { version: snapshot.version, digest: snapshot.digest, changes, areas };
}

const KIND_LABEL = { add: '복원하면 추가', remove: '복원하면 삭제', change: '값 변경', reorder: '순서 변경' };
const show = value => JSON.stringify(value);

// 실행 전에 복원할 버전과 변경 범위를 먼저 보이고, 항목별 차이를 그 아래에 보입니다.
export function renderPlan(plan) {
  const lines = [
    `복원할 버전: ${plan.version}`,
    `사본 지문: ${plan.digest.slice(0, 12)} (기대 지문과 일치)`,
    plan.changes.length === 0 ? '변경 범위: 변경 없음 (사본과 현재 정책이 같습니다)'
      : `변경 범위: ${plan.changes.length}개 항목, 영역 ${plan.areas.join(', ')}`,
  ];
  for (const change of plan.changes) {
    const detail = change.kind === 'add' ? show(change.after) : change.kind === 'remove' ? show(change.before)
      : `${show(change.before)} -> ${show(change.after)}`;
    lines.push(`- [${KIND_LABEL[change.kind]}] ${change.path}: ${detail}`);
  }
  lines.push('이 명령은 아무것도 바꾸지 않았습니다. 실제 복원은 하지 않았습니다.');
  return lines.join('\n');
}
