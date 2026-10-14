import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PolicyCopyError } from '../src/policy-diff.mjs';
import { applyRestore, planApply, renderApplyPlan } from '../src/policy-restore.mjs';

// 사용법: npm run policy:restore -- --snapshot <사본> --expect-sha256 <기대 지문> --only <항목,항목> [--confirm <토큰>]
// --confirm이 없으면 미리보기만 합니다. 시험 정책 파일은 --test-policy, 감사 이력은 --audit로 바꿀 수 있습니다.
const FLAGS = ['--snapshot', '--expect-sha256', '--only', '--confirm', '--test-policy', '--audit'];

export function parseArgs(argv, env = process.env) {
  const values = { '--expect-sha256': env.POLICY_SNAPSHOT_SHA256 };
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!FLAGS.includes(flag) || typeof value !== 'string' || value.startsWith('--')) {
      throw new PolicyCopyError('arguments', '사용법: --snapshot <사본> --expect-sha256 <기대 지문> --only <항목,항목> [--confirm <토큰>]');
    }
    values[flag] = value;
  }
  if (!values['--snapshot']) throw new PolicyCopyError('snapshot_missing', '정책 사본 경로(--snapshot)가 없습니다.');
  return {
    snapshotPath: resolve(values['--snapshot']), expectedSha256: values['--expect-sha256'], only: values['--only'],
    confirm: values['--confirm'],
    ...(values['--test-policy'] ? { testPolicyPath: resolve(values['--test-policy']) } : {}),
    ...(values['--audit'] ? { auditPath: resolve(values['--audit']) } : {}),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = parseArgs(process.argv.slice(2));
    if (options.confirm === undefined) {
      process.stdout.write(`${renderApplyPlan(planApply(options))}\n`);
    } else {
      const { applied, plan } = applyRestore(options);
      process.stdout.write(applied ? `복원 완료: ${plan.changes.length}개 항목을 되돌렸고 감사 이력에 한 줄을 덧붙였습니다.\n`
        : '바꿀 항목이 없어 아무것도 바꾸지 않았습니다.\n');
    }
  } catch (error) {
    const known = error instanceof PolicyCopyError;
    process.stderr.write(`중단: ${known ? `${error.message} (${error.code})` : '정책 복원을 끝내지 못했습니다.'}\n`);
    process.stderr.write('시험 정책과 감사 이력을 바꾸지 않았습니다.\n');
    process.exitCode = 1;
  }
}
