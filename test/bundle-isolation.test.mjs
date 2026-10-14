import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// 제출 묶음(npm run bundle)을 격리 환경에서 실행할 때의 제약을 시험으로 고정합니다.
//  - 불러올 수 있는 것: node:fs, node:path, node:url, node:child_process(git 읽기), node:crypto와 이 저장소의 decider·detect·policy-diff
//  - 보낼 수 있는 요청: 공개 HTTPS 주소로 보내는 GET·HEAD뿐이며, 쓰기 요청이 필요한 점검은 observed를 not_run으로 둔다.
const root = fileURLToPath(new URL('..', import.meta.url));
const NODE_ALLOWED = new Set(['node:fs', 'node:path', 'node:url', 'node:child_process', 'node:crypto']);
const RELATIVE_ALLOWED = new Set(['./decider.mjs', './detect.mjs', './policy-diff.mjs']);
const WRITE_CHECKS = ['anonymous_create_rejected', 'anonymous_update_rejected', 'anonymous_delete_rejected', 'forged_identity_rejected',
  'unsupported_method_rejected', 'anon_direct_create_rejected', 'anon_direct_update_rejected', 'anon_direct_delete_rejected'];

// 단계 1~12의 직접 점검을 모듈 불러오기 추적을 켠 자식 프로세스에서 실제로 실행합니다.
const dir = mkdtempSync(join(tmpdir(), 'bundle-isolation-'));
const traceFile = join(dir, 'trace.jsonl');
const resultFile = join(dir, 'result.json');
const run = spawnSync(process.execPath, [
  '--import', pathToFileURL(join(root, 'test/helpers/trace-register.mjs')).href,
  join(root, 'test/helpers/run-checks.mjs'), root, resultFile,
], { encoding: 'utf8', env: { PATH: process.env.PATH, TRACE_FILE: traceFile } });
const trace = readFileSync(traceFile, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
const outcome = JSON.parse(readFileSync(resultFile, 'utf8'));
const fromSrc = trace.filter((entry) => entry.parent && entry.parent.includes('/src/'));

test('점검 실행이 끝까지 성공하고 추적이 동작한다', () => {
  assert.equal(run.status, 0, run.stderr);
  assert.ok(trace.length > 5, '불러오기 추적이 남아야 한다');
  assert.ok(fromSrc.some((entry) => entry.specifier === './decider.mjs'), '판정기를 불러온 기록이 있어야 한다');
  assert.ok(fromSrc.some((entry) => entry.specifier === './policy-diff.mjs'), '정책 비교 모듈을 불러온 기록이 있어야 한다');
});

test('점검이 불러오는 모듈은 격리 환경에서 허용되는 것뿐이다 (npm 패키지와 node:net이 없다)', () => {
  for (const entry of fromSrc) {
    if (entry.specifier.startsWith('node:')) assert.ok(NODE_ALLOWED.has(entry.specifier), `허용되지 않는 내장 모듈 ${entry.specifier}`);
    else if (entry.specifier.startsWith('.')) assert.ok(RELATIVE_ALLOWED.has(entry.specifier), `허용되지 않는 저장소 모듈 ${entry.specifier}`);
    else assert.fail(`npm 패키지를 불러옴: ${entry.specifier}`);
  }
  const names = new Set(trace.map((entry) => entry.specifier));
  for (const forbidden of ['node:net', '@supabase/supabase-js', 'jose', './verify-login.mjs', './notes-api.mjs', './device-api.mjs', './ops-api.mjs', './recheck.mjs', './auth-api.mjs']) {
    assert.ok(!names.has(forbidden), forbidden);
  }
  // 소스에도 그 모듈들을 가리키는 문장이 없다
  const source = readFileSync(join(root, 'src/attack-check.mjs'), 'utf8');
  assert.doesNotMatch(source, /import\(['"]\.\/(?:notes-api|device-api|ops-api|recheck|verify-login|auth-api)\.mjs['"]\)/u);
  assert.doesNotMatch(source, /from ['"](?:@supabase|jose|node:net)/u);
});

test('제출 묶음 명령 본체가 직접 불러오는 모듈도 허용되는 것뿐이다', () => {
  const bundle = readFileSync(join(root, 'scripts/bundle.mjs'), 'utf8');
  const imports = [...bundle.matchAll(/^import .* from '([^']+)';$/gmu)].map((match) => match[1]);
  assert.ok(imports.length >= 3);
  for (const specifier of imports) assert.ok(NODE_ALLOWED.has(specifier), specifier);
  assert.doesNotMatch(bundle, /from '(?:@supabase|jose|node:net)/u);
});

test('보낸 요청은 모두 공개 HTTPS 주소로 보내는 GET·HEAD이다 (모든 단계)', () => {
  assert.ok(outcome.requests.length >= 10, `요청 ${outcome.requests.length}건`);
  for (const request of outcome.requests) {
    assert.ok(['GET', 'HEAD'].includes(request.method), `${request.method} ${request.url}`);
    assert.ok(request.url.startsWith('https://'), request.url);
  }
});

test('쓰기 요청이 필요한 점검은 보내지 않고 observed를 not_run으로 둔다', () => {
  for (const step of [3, 4, 5, 12]) {
    const results = outcome.steps[step];
    for (const id of WRITE_CHECKS) {
      const found = results.find((attempt) => attempt.attackId === id);
      if (!found) continue; // 해당 단계에 없는 점검
      assert.equal(found.observed, 'not_run', `${step}단계 ${id}`);
      assert.match(found.expected, /쓰기 요청이라 격리 환경에서는 보내지 않음\)$/u, `${step}단계 ${id}`);
    }
  }
  const finalResults = outcome.steps[12];
  for (const id of WRITE_CHECKS) assert.ok(finalResults.some((attempt) => attempt.attackId === id), `12단계에도 ${id} 이름이 그대로 있다`);
  assert.equal(outcome.steps[2].find((attempt) => attempt.attackId === 'api_post_rejected').observed, 'not_run');
});

test('실행하지 않은 점검은 모든 단계에서 observed가 정확히 not_run이고 옛 미실행 문장이 남지 않는다', () => {
  for (const [step, results] of Object.entries(outcome.steps)) {
    for (const attempt of results) {
      assert.ok(!attempt.observed.startsWith('미실행'), `${step}단계 ${attempt.attackId}`);
      if (attempt.observed === 'not_run') assert.match(attempt.expected, /\(.+\)$/u, `${step}단계 ${attempt.attackId}: 이유`);
    }
  }
  const notRun = outcome.steps[12].filter((attempt) => attempt.observed === 'not_run').map((attempt) => attempt.attackId);
  for (const id of ['logged_in_own_crud', 'cross_user_access', 'authenticated_direct_rejected', 'original_url_no_notes', 'anon_direct_read_rejected']) {
    assert.ok(notRun.includes(id), id);
  }
});

test('모든 단계의 점검이 제출 묶음 기준(1~20개, 세 항목만, 300자 이하, 이름 중복 없음)을 지킨다', () => {
  for (const [step, results] of Object.entries(outcome.steps)) {
    assert.ok(results.length >= 1 && results.length <= 20, `${step}단계 ${results.length}개`);
    const ids = new Set();
    for (const attempt of results) {
      assert.equal(Object.keys(attempt).sort().join(','), 'attackId,expected,observed', `${step}단계`);
      assert.match(attempt.attackId, /^[a-z0-9][a-z0-9_.-]{0,79}$/iu);
      assert.ok(attempt.expected.trim() && attempt.expected.length <= 300, `${step}단계 ${attempt.attackId} expected ${attempt.expected.length}자`);
      assert.ok(attempt.observed.trim() && attempt.observed.length <= 300, `${step}단계 ${attempt.attackId} observed ${attempt.observed.length}자`);
      assert.ok(!ids.has(attempt.attackId), `${step}단계 ${attempt.attackId} 중복`);
      ids.add(attempt.attackId);
    }
  }
});
