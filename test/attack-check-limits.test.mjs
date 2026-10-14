import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runAttackChecks } from '../src/attack-check.mjs';

// scripts/bundle.mjs가 직접 점검 결과에 요구하는 모양을 같은 기준으로 미리 확인합니다.
// 실제 배포 주소로 요청하지 않도록 fetch를 막아, 요청이 필요한 점검은 "실패해 확인하지 못함"으로 기록되게 합니다.
test('현재 단계의 직접 점검 결과는 제출 묶음 기준(1~20개, 세 항목만, 300자 이하)을 지킨다', async () => {
  const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
  const blocked = mock.method(globalThis, 'fetch', async () => { throw new Error('network_blocked'); });
  let results;
  try { results = await runAttackChecks(config); } finally { blocked.mock.restore(); }
  assert.ok(Array.isArray(results) && results.length >= 1 && results.length <= 20, `점검 ${results.length}개`);
  const ids = new Set();
  for (const attempt of results) {
    assert.equal(Object.keys(attempt).sort().join(','), 'attackId,expected,observed');
    assert.match(attempt.attackId, /^[a-z0-9][a-z0-9_.-]{0,79}$/iu);
    for (const field of ['expected', 'observed']) {
      assert.equal(typeof attempt[field], 'string');
      assert.ok(attempt[field].trim().length > 0, `${attempt.attackId}.${field} 비어 있음`);
      assert.ok(attempt[field].length <= 300, `${attempt.attackId}.${field} ${attempt[field].length}자`);
    }
    assert.ok(!ids.has(attempt.attackId), `${attempt.attackId} 중복`);
    ids.add(attempt.attackId);
  }
  assert.ok(!ids.has('detect_local') || config.step === 9, '10단계부터 detect_local은 decider_local에 합쳐 있음');
});

test('10단계부터의 로컬 연습은 local_practice 한 항목에 합치고 요청을 보내지 않으므로 not_run으로 적는다', async () => {
  const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
  if (config.step < 10) return;
  const blocked = mock.method(globalThis, 'fetch', async () => { throw new Error('network_blocked'); });
  let results;
  try { results = await runAttackChecks(config); } finally { blocked.mock.restore(); }
  for (const gone of ['decider_local', 'detect_local', 'restore_local']) assert.ok(!results.some((attempt) => attempt.attackId === gone), gone);
  const merged = results.find((attempt) => attempt.attackId === 'local_practice');
  assert.ok(merged, 'local_practice');
  assert.equal(merged.observed, 'not_run');
  assert.match(merged.expected, /로컬 연습이라 요청을 보내지 않음. 결과는 npm run recheck와 node --test에서 확인\)$/u);
  assert.ok(merged.expected.length <= 300);
});
