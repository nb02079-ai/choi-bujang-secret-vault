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

test('10단계부터의 로컬 점검은 기대와 같고 미실행을 밝힌다', async () => {
  const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
  if (config.step < 10) return;
  const blocked = mock.method(globalThis, 'fetch', async () => { throw new Error('network_blocked'); });
  let results;
  try { results = await runAttackChecks(config); } finally { blocked.mock.restore(); }
  // 11단계부터는 판정기·탐지, 메모 복원, 기기 승인 연습을 local_practice 한 항목에 합쳐 20개 상한을 지킨다.
  const expectedIds = config.step >= 11 ? ['local_practice'] : ['decider_local', 'restore_local'];
  if (config.step >= 11) {
    for (const gone of ['decider_local', 'restore_local', 'detect_local']) assert.ok(!results.some(attempt => attempt.attackId === gone), gone);
    const merged = results.find(attempt => attempt.attackId === 'local_practice');
    assert.match(merged.observed, /판정기·탐지 기대와 같음, 메모 복원 기대와 같음, 기기 승인 기대와 같음/u);
  }
  for (const id of expectedIds) {
    const found = results.find(attempt => attempt.attackId === id);
    assert.ok(found, id);
    assert.match(found.observed, /기대와 같음/u, id);
    assert.doesNotMatch(found.observed, /기대와 다름/u, id);
    assert.match(found.observed, /심판 판정이 아님/u, id);
    assert.match(found.observed, /미실행/u, id);
  }
});
