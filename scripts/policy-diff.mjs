import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PolicyCopyError, planRestore, renderPlan } from '../src/policy-diff.mjs';

// 사용법: npm run policy:diff -- --snapshot <사본 경로> --expect-sha256 <기대 지문>
// 기대 지문은 환경변수 POLICY_SNAPSHOT_SHA256으로도 줄 수 있습니다. 이 명령은 아무것도 바꾸지 않습니다.
export function parseArgs(argv, env = process.env) {
  const options = { snapshot: undefined, expect: env.POLICY_SNAPSHOT_SHA256 };
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if ((flag !== '--snapshot' && flag !== '--expect-sha256') || typeof value !== 'string' || value.startsWith('--')) {
      throw new PolicyCopyError('arguments', '사용법: --snapshot <사본 경로> --expect-sha256 <기대 지문>');
    }
    if (flag === '--snapshot') options.snapshot = value;
    else options.expect = value;
  }
  if (!options.snapshot) throw new PolicyCopyError('snapshot_missing', '정책 사본 경로(--snapshot)가 없습니다.');
  return options;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { snapshot, expect } = parseArgs(process.argv.slice(2));
    process.stdout.write(`${renderPlan(planRestore(resolve(snapshot), expect))}\n`);
  } catch (error) {
    const known = error instanceof PolicyCopyError;
    process.stderr.write(`중단: ${known ? `${error.message} (${error.code})` : '정책 비교를 끝내지 못했습니다.'}\n`);
    process.stderr.write('복원할 버전과 변경 범위를 확인하지 못해 아무것도 보이지 않고 아무것도 바꾸지 않았습니다.\n');
    process.exitCode = 1;
  }
}
