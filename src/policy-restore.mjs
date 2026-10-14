// 10단계: 검증한 안전 정책 사본으로 시험 정책 파일(policy/test-policy.json)의 지정한 항목만 되돌립니다.
// 실제 운영 정책(src/decider.mjs, aleph.config.json)은 건드리지 않습니다.
// 처음 실행은 미리보기만 하고, 미리보기에 나온 확인 토큰을 다시 넣어야 씁니다.
// 감사 이력(policy/audit.log)은 덧붙이기만 하고, 지정하지 않은 항목은 현재 값을 그대로 둡니다.
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PolicyCopyError, canonical, currentPolicy, diffPolicy, loadSnapshot, validatePolicy } from './policy-diff.mjs';

export const TEST_POLICY_URL = new URL('../policy/test-policy.json', import.meta.url);
export const AUDIT_LOG_URL = new URL('../policy/audit.log', import.meta.url);
const AREA_NAMES = ['ruleIds', 'reasonCodes', 'zoneRoutes', 'writeMethods', 'functionNames', 'stepUp', 'trustedSources', 'allowedRoutes'];
const clone = value => JSON.parse(JSON.stringify(value));
const asPath = location => (location instanceof URL ? fileURLToPath(location) : location);

// 시험 정책 파일이 없으면 현재 코드 정책을 시험 정책으로 봅니다.
export function loadTestPolicy(path = TEST_POLICY_URL, options) {
  if (!existsSync(path)) return currentPolicy(options);
  let policy;
  try { policy = JSON.parse(readFileSync(path, 'utf8')); } catch { throw new PolicyCopyError('test_policy_invalid', '시험 정책 파일을 읽을 수 없습니다.'); }
  return validatePolicy(policy, 'test_policy_invalid');
}

// --only 값: 항목 이름 또는 항목.하위이름만 받습니다. 비어 있거나 all이면 중단합니다.
export function parseScope(only) {
  const list = Array.isArray(only) ? only : typeof only === 'string' ? only.split(',') : [];
  const ok = list.length >= 1 && list.length <= 20 && list.every(item => typeof item === 'string'
    && /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)?$/u.test(item) && AREA_NAMES.includes(item.split('.')[0]));
  if (!ok) throw new PolicyCopyError('only_invalid', '복원할 항목(--only)을 정확히 지정해야 합니다. 전체 복원은 허용하지 않습니다.');
  return [...new Set(list)].sort();
}

const inScope = (path, scope) => scope.some(item => path === item || path.startsWith(`${item}.`));

function merged(current, restored, scope) {
  const next = clone(current);
  for (const item of scope) {
    const [area, child] = item.split('.');
    if (child === undefined) next[area] = clone(restored[area]);
    else if (restored[area] !== null && typeof restored[area] === 'object' && !Array.isArray(restored[area]) && Object.hasOwn(restored[area], child)) {
      next[area][child] = clone(restored[area][child]);
    } else if (next[area] !== null && typeof next[area] === 'object' && !Array.isArray(next[area])) delete next[area][child];
  }
  return validatePolicy(next, 'merged_invalid');
}

export function planApply({ snapshotPath, expectedSha256, only, testPolicyPath = TEST_POLICY_URL, ...options }) {
  const scope = parseScope(only);
  const snapshot = loadSnapshot(snapshotPath, expectedSha256);
  const current = loadTestPolicy(testPolicyPath, options);
  const all = diffPolicy(current, snapshot.policy);
  const changes = all.filter(change => inScope(change.path, scope));
  const next = merged(current, snapshot.policy, scope);
  const token = createHash('sha256').update(canonical({ version: snapshot.version, digest: snapshot.digest, scope, changes })).digest('hex').slice(0, 12);
  return { version: snapshot.version, digest: snapshot.digest, scope, changes, kept: all.length - changes.length, token, next, current };
}

const KIND_LABEL = { add: '복원하면 추가', remove: '복원하면 삭제', change: '값 변경', reorder: '순서 변경' };
const show = value => JSON.stringify(value);

export function renderApplyPlan(plan) {
  const lines = [
    `복원할 버전: ${plan.version}`,
    `사본 지문: ${plan.digest.slice(0, 12)} (기대 지문과 일치)`,
    `복원 범위: ${plan.scope.join(', ')}`,
    plan.changes.length === 0 ? '바뀔 항목: 없음 (범위 안에서 사본과 시험 정책이 같습니다)' : `바뀔 항목: ${plan.changes.length}개`,
  ];
  for (const change of plan.changes) {
    const detail = change.kind === 'add' ? show(change.after) : change.kind === 'remove' ? show(change.before)
      : `${show(change.before)} -> ${show(change.after)}`;
    lines.push(`- [${KIND_LABEL[change.kind]}] ${change.path}: ${detail}`);
  }
  lines.push(`그대로 두는 항목: ${plan.kept}개 (범위 밖 차이). 감사 이력은 덧붙이기만 하고 지우거나 고치지 않습니다.`);
  if (plan.changes.length > 0) {
    lines.push(`확인 토큰: ${plan.token}`, '아직 아무것도 바꾸지 않았습니다. 위 항목이 맞으면 같은 명령에 --confirm <확인 토큰>을 붙여 다시 실행하세요.');
  } else {
    lines.push('바꿀 항목이 없어 아무것도 바꾸지 않습니다.');
  }
  return lines.join('\n');
}

// 감사 이력에는 값 원문 없이 항목 경로와 종류별 건수만 남깁니다.
function summarize(changes) {
  const counts = new Map();
  for (const { path, kind } of changes) counts.set(`${path} ${kind}`, (counts.get(`${path} ${kind}`) ?? 0) + 1);
  return [...counts].map(([key, count]) => { const [path, kind] = key.split(' '); return { path, kind, count }; });
}

function writeAtomic(path, text) {
  mkdirSync(dirname(path), { recursive: true });
  const temp = `${path}.tmp-${process.pid}`;
  writeFileSync(temp, text, { flag: 'wx' });
  renameSync(temp, path);
}

// 확인 토큰이 맞을 때만 씁니다. 쓴 뒤 다시 읽어 확인하고, 확인이나 감사 기록에 실패하면 이전 내용으로 되돌립니다.
export function applyRestore({ confirm, auditPath: auditLocation = AUDIT_LOG_URL, testPolicyPath: policyLocation = TEST_POLICY_URL, now = () => new Date(), ...rest }) {
  const auditPath = asPath(auditLocation);
  const testPolicyPath = asPath(policyLocation);
  const plan = planApply({ ...rest, testPolicyPath });
  if (plan.changes.length === 0) return { applied: false, plan };
  if (typeof confirm !== 'string' || confirm !== plan.token) {
    throw new PolicyCopyError('confirm_mismatch', '확인 토큰이 없거나 바뀔 항목과 맞지 않아 아무것도 바꾸지 않았습니다.');
  }
  const previous = existsSync(testPolicyPath) ? readFileSync(testPolicyPath) : null;
  const rollback = () => { if (previous === null) { try { unlinkSync(testPolicyPath); } catch { /* 이미 없음 */ } } else writeFileSync(testPolicyPath, previous); };
  let previousAudit = '';
  try { previousAudit = existsSync(auditPath) ? readFileSync(auditPath, 'utf8') : ''; } catch { throw new PolicyCopyError('audit_unreadable', '감사 이력을 읽을 수 없어 아무것도 바꾸지 않았습니다.'); }
  try {
    writeAtomic(testPolicyPath, `${JSON.stringify(plan.next, null, 2)}\n`);
    const after = loadTestPolicy(testPolicyPath);
    const expected = canonical(plan.next);
    if (canonical(after) !== expected) throw new PolicyCopyError('verify_failed', '쓴 뒤 다시 읽은 시험 정책이 계획과 다릅니다.');
    const entry = { event: 'policy_restore', at: now().toISOString(), version: plan.version, snapshot: plan.digest.slice(0, 12),
      token: plan.token, scope: plan.scope, changes: summarize(plan.changes) };
    mkdirSync(dirname(auditPath), { recursive: true });
    appendFileSync(auditPath, `${previousAudit === '' || previousAudit.endsWith('\n') ? '' : '\n'}${JSON.stringify(entry)}\n`);
    if (!readFileSync(auditPath, 'utf8').startsWith(previousAudit)) throw new PolicyCopyError('audit_failed', '감사 이력의 기존 내용이 달라졌습니다.');
  } catch (error) {
    rollback();
    if (error instanceof PolicyCopyError) throw error;
    throw new PolicyCopyError('apply_failed', '시험 정책을 쓰지 못해 이전 상태로 되돌렸습니다.');
  }
  return { applied: true, plan };
}
