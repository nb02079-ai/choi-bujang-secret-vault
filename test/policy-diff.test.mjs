import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describePolicy, RULE_IDS } from '../src/decider.mjs';
import { PolicyCopyError, SNAPSHOT_SCHEMA, currentPolicy, diffPolicy, loadSnapshot, planRestore, renderPlan, snapshotDigest } from '../src/policy-diff.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const dir = mkdtempSync(join(tmpdir(), 'policy-diff-'));
const clone = value => JSON.parse(JSON.stringify(value));
let counter = 0;
const write = (snapshot) => {
  const path = join(dir, `snapshot-${counter += 1}.json`);
  writeFileSync(path, JSON.stringify(snapshot, null, 2));
  return path;
};
const make = (policy, version = 'v1') => {
  const body = { schema: SNAPSHOT_SCHEMA, version, policy };
  return { ...body, sha256: snapshotDigest(body) };
};
const reasonOf = (action) => { try { action(); } catch (error) { assert.ok(error instanceof PolicyCopyError, String(error)); return error.code; } return 'no_error'; };

test('현재 정책은 판정기의 읽기 전용 복사본이고 바꿔도 판정기에 영향이 없다', () => {
  const policy = describePolicy();
  assert.deepEqual(policy.ruleIds, [...RULE_IDS]);
  policy.ruleIds.push('forged');
  policy.zoneRoutes.notes.push('GET /notes');
  policy.functionNames.length = 0;
  const again = describePolicy();
  assert.deepEqual(again.ruleIds, [...RULE_IDS]);
  assert.ok(!again.zoneRoutes.notes.includes('GET /notes'));
  assert.ok(again.functionNames.includes('export'));
  assert.deepEqual(currentPolicy().allowedRoutes, JSON.parse(readFileSync(join(root, 'aleph.config.json'), 'utf8')).allowedRoutes);
});

test('사본이 현재 정책과 같으면 변경 없음으로 보여 준다', () => {
  const snapshot = make(currentPolicy(), 'v1');
  const plan = planRestore(write(snapshot), snapshot.sha256);
  assert.equal(plan.version, 'v1');
  assert.deepEqual(plan.changes, []);
  assert.match(renderPlan(plan), /변경 범위: 변경 없음/u);
});

test('복원할 버전과 변경 범위가 항목별 차이보다 먼저 나온다', () => {
  const policy = clone(currentPolicy());
  policy.functionNames = policy.functionNames.filter(name => name !== 'mine');
  policy.zoneRoutes.notes.push('GET /notes');
  policy.allowedRoutes = policy.allowedRoutes.slice(0, 2);
  policy.stepUp.burstCountMin = 7;
  policy.ruleIds = [...policy.ruleIds].reverse();
  const snapshot = make(policy, 'pre-breach-3');
  const plan = planRestore(write(snapshot), snapshot.sha256);
  const text = renderPlan(plan);
  const lines = text.split('\n');
  assert.equal(lines[0], '복원할 버전: pre-breach-3');
  assert.equal(lines[1], `사본 지문: ${snapshot.sha256.slice(0, 12)} (기대 지문과 일치)`);
  assert.match(lines[2], /^변경 범위: \d+개 항목, 영역 /u);
  assert.equal(lines.at(-1), '이 명령은 아무것도 바꾸지 않았습니다. 실제 복원은 하지 않았습니다.');
  const kinds = plan.changes.map(change => `${change.kind}:${change.path}`);
  assert.ok(kinds.includes('remove:functionNames'), '사본에 없는 mine은 복원하면 삭제');
  assert.ok(kinds.includes('add:zoneRoutes.notes'), '사본에만 있는 경로는 복원하면 추가');
  assert.ok(kinds.includes('remove:allowedRoutes'));
  assert.ok(kinds.includes('change:stepUp.burstCountMin'));
  assert.ok(kinds.includes('add:functionNames') === false);
  assert.ok(plan.areas.includes('ruleIds') && plan.areas.includes('stepUp'));
  assert.match(text, /\[복원하면 삭제\] functionNames: "mine"/u);
  assert.match(text, /\[값 변경\] stepUp\.burstCountMin: 10 -> 7/u);
  const reordered = diffPolicy(currentPolicy(), { ...currentPolicy(), ruleIds: [...RULE_IDS].reverse() });
  assert.deepEqual(reordered.map(change => change.kind), ['reorder']);
});

test('사본이 없으면 중단한다', () => {
  assert.equal(reasonOf(() => loadSnapshot(join(dir, 'none.json'), 'a'.repeat(64))), 'snapshot_missing');
  assert.equal(reasonOf(() => loadSnapshot(dir, 'a'.repeat(64))), 'snapshot_unreadable');
});

test('기대 지문이 없거나 형식이 틀리거나 다르면 중단한다', () => {
  const snapshot = make(currentPolicy());
  const path = write(snapshot);
  for (const missing of [undefined, null, '']) assert.equal(reasonOf(() => loadSnapshot(path, missing)), 'expected_missing');
  for (const bad of ['abc', 'A'.repeat(64), 7, 'g'.repeat(64)]) {
    assert.ok(['expected_format', 'expected_missing'].includes(reasonOf(() => loadSnapshot(path, bad))), String(bad));
  }
  assert.equal(reasonOf(() => loadSnapshot(path, 'b'.repeat(64))), 'expected_mismatch');
  assert.equal(loadSnapshot(path, snapshot.sha256).digest, snapshot.sha256);
});

test('내용을 바꾼 사본은 지문이 맞아도 기대 지문이 달라 중단한다', () => {
  const original = make(currentPolicy());
  const forgedPolicy = clone(currentPolicy());
  forgedPolicy.zoneRoutes.notes.push('GET /notes');
  // 공격자가 내용과 사본 안의 지문을 함께 고친 경우
  const forged = make(forgedPolicy);
  assert.equal(reasonOf(() => loadSnapshot(write(forged), original.sha256)), 'expected_mismatch');
  // 내용만 고치고 지문은 그대로 둔 경우
  const half = { ...original, policy: forgedPolicy };
  assert.equal(reasonOf(() => loadSnapshot(write(half), original.sha256)), 'digest_mismatch');
  // 지문만 고친 경우
  assert.equal(reasonOf(() => loadSnapshot(write({ ...original, sha256: 'c'.repeat(64) }), original.sha256)), 'digest_mismatch');
});

test('형식이 틀린 사본은 중단한다', () => {
  const good = make(currentPolicy());
  const cases = {
    snapshot_not_json: () => { const path = join(dir, 'broken.json'); writeFileSync(path, '{ not json'); return path; },
    snapshot_fields: () => write({ ...good, extra: 1 }),
    snapshot_schema: () => write({ ...good, schema: 'other.v1' }),
    snapshot_version: () => write({ ...good, version: '../escape' }),
    snapshot_policy: () => write({ ...good, policy: { ...good.policy, unknownArea: ['x'] } }),
  };
  for (const [code, build] of Object.entries(cases)) assert.equal(reasonOf(() => loadSnapshot(build(), good.sha256)), code, code);
  const typed = clone(good);
  typed.policy.stepUp.oddHourMax = 'five';
  assert.equal(reasonOf(() => loadSnapshot(write(typed), good.sha256)), 'snapshot_policy');
  const missingArea = clone(good);
  delete missingArea.policy.writeMethods;
  assert.equal(reasonOf(() => loadSnapshot(write(missingArea), good.sha256)), 'snapshot_policy');
  const array = join(dir, 'array.json');
  writeFileSync(array, '[]');
  assert.equal(reasonOf(() => loadSnapshot(array, good.sha256)), 'snapshot_fields');
  const big = join(dir, 'big.json');
  writeFileSync(big, ' '.repeat(300 * 1024));
  assert.equal(reasonOf(() => loadSnapshot(big, good.sha256)), 'snapshot_too_large');
});

test('아무것도 바꾸지 않는다: 정책 파일 해시가 실행 전후로 같고 소스에 쓰기 호출이 없다', () => {
  const files = ['src/decider.mjs', 'aleph.config.json', 'src/policy-diff.mjs'].map(name => join(root, name));
  const hash = path => createHash('sha256').update(readFileSync(path)).digest('hex');
  const snapshot = make(currentPolicy());
  const path = write(snapshot);
  const before = [...files, path].map(hash);
  const listing = readdirSync(dir).sort().join();
  planRestore(path, snapshot.sha256);
  assert.deepEqual([...files, path].map(hash), before);
  assert.equal(readdirSync(dir).sort().join(), listing);
  const source = readFileSync(join(root, 'src/policy-diff.mjs'), 'utf8');
  assert.doesNotMatch(source, /\b(writeFile|writeFileSync|appendFile|unlink|rename|mkdir|rmSync|copyFile|fetch|child_process|XMLHttpRequest|process\.env)\b/u);
  assert.doesNotMatch(source, /import\s+[^;]*from\s+'node:(?!crypto|fs'|fs\b)/u);
});

test('명령: 정상 사본은 버전·범위를 먼저 보이고, 실패하면 아무 차이도 보이지 않고 종료 코드 1이다', () => {
  const policy = clone(currentPolicy());
  policy.functionNames = policy.functionNames.slice(1);
  const snapshot = make(policy, 'v-cli');
  const run = (args, env = {}) => spawnSync(process.execPath, [join(root, 'scripts/policy-diff.mjs'), ...args],
    { encoding: 'utf8', env: { PATH: process.env.PATH, ...env } });
  const ok = run(['--snapshot', write(snapshot), '--expect-sha256', snapshot.sha256]);
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /^복원할 버전: v-cli\n사본 지문: [0-9a-f]{12} /u);
  assert.match(ok.stdout, /\[복원하면 삭제\] functionNames: "export"/u);
  const viaEnv = run(['--snapshot', write(snapshot)], { POLICY_SNAPSHOT_SHA256: snapshot.sha256 });
  assert.equal(viaEnv.status, 0);
  for (const args of [
    ['--snapshot', join(dir, 'none.json'), '--expect-sha256', snapshot.sha256],
    ['--snapshot', write(snapshot)],
    ['--snapshot', write(snapshot), '--expect-sha256', 'd'.repeat(64)],
    ['--expect-sha256', snapshot.sha256],
    ['--snapshot'],
    ['--restore', 'now'],
  ]) {
    const failed = run(args);
    assert.equal(failed.status, 1, args.join(' '));
    assert.match(failed.stderr, /^중단: /u);
    assert.doesNotMatch(failed.stdout, /복원할 버전|변경 범위/u);
    assert.doesNotMatch(failed.stderr, /\n\s+at /u, '스택 추적을 출력하지 않음');
  }
});

test('출력에 비밀값이 없다', () => {
  const policy = clone(currentPolicy());
  policy.allowedRoutes = [];
  const snapshot = make(policy);
  const text = renderPlan(planRestore(write(snapshot), snapshot.sha256));
  // 키 모양 패턴은 실행할 때 조립해 저장소 파일에 키 형태 글자가 남지 않게 합니다.
  const shapes = [`sb_${['sec', 'ret'].join('')}_[A-Za-z0-9_-]{6,}`, `s${'k'}-[A-Za-z0-9]{20,}`,
    'eyJ[A-Za-z0-9_-]{12,}\\.', `PRIV${'ATE KEY'}`, 'Bearer'];
  assert.doesNotMatch(text, new RegExp(shapes.join('|'), 'u'));
});
