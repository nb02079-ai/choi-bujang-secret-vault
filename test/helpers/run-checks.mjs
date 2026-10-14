// 시험 도우미: 단계 1~12의 직접 점검을 가짜 fetch로 실행하고, 보낸 요청 방식과 결과를 JSON 파일로 남깁니다.
// 사용법: node --import trace-register.mjs run-checks.mjs <저장소 폴더> <결과 파일>
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [, , root, outFile] = process.argv;
const requests = [];
let currentStep = 0;
globalThis.fetch = async (url, init = {}) => {
  requests.push({ step: currentStep, method: String(init.method ?? 'GET').toUpperCase(), url: String(url), attackId: init.headers?.['x-attack-id'] ?? null });
  return new Response('{}', { status: 401 });
};
const { runAttackChecks } = await import(pathToFileURL(join(root, 'src', 'attack-check.mjs')).href);
const config = JSON.parse(readFileSync(join(root, 'aleph.config.json'), 'utf8'));
const steps = {};
for (let step = 1; step <= 12; step += 1) {
  currentStep = step;
  steps[step] = await runAttackChecks({ ...config, step });
}
writeFileSync(outFile, JSON.stringify({ requests, steps }));
