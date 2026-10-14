import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderReport, runRecheck } from '../src/recheck.mjs';

// 사용법: npm run recheck [-- --deployed https://배포주소 --out 폴더]
// 1~11단계의 정상·금지 요청을 다시 실행해 기대, 실제, 요청 ID, 확인 시각을 한 표로 만듭니다.
// --deployed를 주면 토큰 없이 보낼 수 있는 요청만 배포 주소로 실제 전송합니다. 계정 토큰과 비밀값은 받지 않습니다.
// 불일치가 하나라도 있으면 종료 코드 1, 사용법이 틀리면 2입니다. 미실행은 실패로도 통과로도 세지 않습니다.
export class UsageError extends Error {}

export function parseArgs(argv) {
  const options = { baseUrl: null, out: resolve('artifacts', 'recheck') };
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if ((flag !== '--deployed' && flag !== '--out') || typeof value !== 'string' || value.startsWith('--')) {
      throw new UsageError('사용법: npm run recheck [-- --deployed https://배포주소 --out 폴더]');
    }
    if (flag === '--out') {
      options.out = resolve(value);
      continue;
    }
    let url;
    try { url = new URL(value); } catch { throw new UsageError('--deployed에는 https 주소를 주세요.'); }
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
      throw new UsageError('--deployed에는 경로·쿼리·계정 정보가 없는 https 주소만 줄 수 있습니다.');
    }
    options.baseUrl = url.origin;
  }
  return options;
}

export const exitCodeFor = (result) => (result.summary.mismatch > 0 ? 1 : 0);

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = parseArgs(process.argv.slice(2));
    const result = await runRecheck({ baseUrl: options.baseUrl });
    const report = renderReport(result);
    process.stdout.write(`${report}\n`);
    mkdirSync(options.out, { recursive: true });
    const stamp = result.generatedAt.replace(/[-:]/gu, '').replace(/\.\d+Z$/u, 'Z');
    writeFileSync(join(options.out, `recheck-${stamp}.md`), `${report}\n`);
    writeFileSync(join(options.out, `recheck-${stamp}.json`), `${JSON.stringify(result, null, 2)}\n`);
    process.stdout.write(`저장: ${join(options.out, `recheck-${stamp}`)}.md / .json\n`);
    process.exitCode = exitCodeFor(result);
  } catch (error) {
    process.stderr.write(`${error instanceof UsageError ? error.message : '재확인 표를 만들지 못했습니다.'}\n`);
    process.exitCode = error instanceof UsageError ? 2 : 1;
  }
}
