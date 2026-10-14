// 시험 도우미: 모듈을 불러올 때마다 어떤 이름을 어디서 불러왔는지 파일에 한 줄씩 남깁니다.
import { appendFileSync } from 'node:fs';

export async function resolve(specifier, context, nextResolve) {
  if (process.env.TRACE_FILE) {
    appendFileSync(process.env.TRACE_FILE, `${JSON.stringify({ specifier, parent: context.parentURL ?? null })}\n`);
  }
  return nextResolve(specifier, context);
}
