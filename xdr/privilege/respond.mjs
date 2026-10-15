// 권한 가로채기(계정·그룹 변경, 관리자 권한 사용) 경보용입니다. decide.mjs 의 결과를 받아 (1) 알림을 xdr/alerts.log 에 한 줄씩 쌓고 (2) 평소와 다른 권한 상승이 뚜렷하게 확인된 차단 후보만 ZTNA 판정기의 거부 규칙(세션 거둠)으로 넣습니다.
// decide.mjs 는 판단만 하고 이 파일을 모릅니다. 판정기(src/decider.mjs)의 기존 규칙은 고치지 않습니다.
// 거부 규칙은 만료 시각과 근거 경보 번호를 가지며, 정상 사용자를 막지 않도록 아래 안전장치를 모두 통과해야 들어갑니다.
//   - 차단 후보(block, 확신도 0.85 이상)만 / 근거 경보 번호가 있어야 함
//   - 막는 대상은 계정 한 개뿐입니다(이름 하나, 범위·와일드카드 없음). 같은 주소의 다른 계정은 막지 않습니다.
//   - 지킬 계정 목록(수업용 관리 계정·서비스 계정 등)은 제외 / 이미 거둔 계정은 중복해서 넣지 않음 / 동시에 거두는 계정 수에 상한 / 만료는 짧게(기본 15분), 24시간을 넘기지 않음
// 이 파일이 만든 거부 규칙은 메모리에만 있고 프로세스가 끝나면 사라집니다. 알림 로그만 파일에 남습니다.
import { appendFile, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

export const RULE_ID = 'xdr.privilege.revoke';
// 운영 등록부에 이 코드가 없으면 엔진은 응답을 허용하지 않으므로 거부 쪽으로 실패합니다. 등록 여부는 운영 측과 확인해야 합니다.
export const DEFAULT_REASON_CODE = 'privilege_session_revoked';
export const DENY_TTL_MS = 15 * 60 * 1000;
export const MIN_TTL_MS = 60 * 1000;
export const MAX_TTL_MS = 24 * 60 * 60 * 1000;
export const MAX_RULES = 50;
// 수업용 관리 계정과 서비스 계정은 기본으로 지킵니다. 운영 측 목록으로 바꿀 수 있습니다.
export const PROTECTED_ACCOUNTS = Object.freeze(['admin01', 'svc-lab']);
const BLOCK_AT = 0.85;
const DEFAULT_LOG = fileURLToPath(new URL('../alerts.log', import.meta.url));

const ID = /^[A-Za-z0-9._-]{1,64}$/u;
const normalize = (value) => (typeof value === 'string' ? value.trim().toLowerCase() : '');
const isAccount = (value) => ID.test(value);

const iso = (ms) => new Date(ms).toISOString();

export function createDenyList({ now = Date.now, ttlMs = DENY_TTL_MS, maxRules = MAX_RULES, protectedAccounts = PROTECTED_ACCOUNTS } = {}) {
  const ttl = Math.min(MAX_TTL_MS, Math.max(MIN_TTL_MS, Number.isFinite(ttlMs) ? ttlMs : DENY_TTL_MS));
  const limit = Number.isInteger(maxRules) && maxRules > 0 ? maxRules : MAX_RULES;
  const protectedSet = new Set(protectedAccounts.map(normalize).filter(Boolean));
  const rules = new Map();

  const prune = () => {
    const at = now();
    for (const [account, rule] of rules) if (rule.expiresAtMs <= at) rules.delete(account);
  };
  const publicRule = (rule) => Object.freeze({
    ruleId: rule.ruleId, type: 'deny', account: rule.account, alertId: rule.alertId,
    confidence: rule.confidence, createdAt: iso(rule.createdAtMs), expiresAt: iso(rule.expiresAtMs),
  });

  return {
    // 규칙을 넣으면 { rule }, 넣지 않으면 { skipped: 이유 } 를 돌려줍니다. 던지지 않습니다.
    add(alert, decision) {
      if (decision?.action !== 'block' || !Number.isFinite(decision.confidence) || decision.confidence < BLOCK_AT || decision.confidence > 1) {
        return { skipped: 'not_block' };
      }
      const alertId = alert?.id;
      if (typeof alertId !== 'string' || !ID.test(alertId)) return { skipped: 'no_alert_id' };
      const account = normalize(alert.data?.srcuser);
      if (!isAccount(account)) return { skipped: 'bad_account' };
      if (protectedSet.has(account)) return { skipped: 'protected_account' };
      prune();
      if (rules.has(account)) return { skipped: 'duplicate' };
      if (rules.size >= limit) return { skipped: 'rule_limit' };
      const createdAtMs = now();
      const rule = { ruleId: `${RULE_ID}.${alertId}`, account, alertId, confidence: decision.confidence,
        createdAtMs, expiresAtMs: createdAtMs + ttl };
      rules.set(account, rule);
      return { rule: publicRule(rule) };
    },
    // 지금 유효한 거부 규칙이 이 계정에 있으면 돌려주고, 없거나 만료됐으면 null 입니다.
    match(account) {
      const key = normalize(account);
      if (!isAccount(key)) return null;
      prune();
      const rule = rules.get(key);
      return rule ? publicRule(rule) : null;
    },
    active() {
      prune();
      return [...rules.values()].map(publicRule);
    },
  };
}

// 판정기를 감싸 거부만 더합니다. 허용으로 바꾸는 길은 없고, 규칙에 걸리지 않으면 원래 판정기가 그대로 답합니다.
// 판정 요청에는 계정 필드가 없으므로, 계정은 운영 쪽이 엔진이 확인한 세션에서 알려 주는 함수(accountOf)로만 얻습니다.
// 기본값은 계정을 모른다고 답하므로 아무것도 막지 않습니다. 요청 본문의 userId 를 믿고 꺼내 쓰지 마세요.
export function withPrivilegeRevoke(baseDecide, { denyList, accountOf = () => null, reasonCode = DEFAULT_REASON_CODE } = {}) {
  if (typeof baseDecide !== 'function' || !denyList || typeof denyList.match !== 'function') {
    throw new TypeError('invalid_deny_connection');
  }
  return async function decideWithPrivilegeRevoke(request) {
    let account = null;
    try { account = accountOf(request); } catch { account = null; }
    if (denyList.match(account)) {
      return { schema: 'aleph.decision.v1', requestId: request?.requestId, decision: 'deny', reasonCode, ruleIds: [RULE_ID] };
    }
    return baseDecide(request);
  };
}

const clean = (value) => String(value).replace(/[^\x20-\x7E가-힣]/gu, ' ').replace(/\s+/gu, ' ').trim();

// 알림 한 줄을 xdr/alerts.log 에 덧붙입니다. 기록하는 값은 경보 번호·행동·확신도·고정 문구·규칙 번호뿐입니다(경보 설명·계정·주소는 싣지 않음).
async function writeLine(logFile, now, kind, alert, decision, extra) {
  const id = typeof alert?.id === 'string' && ID.test(alert.id) ? alert.id : '-';
  const parts = [iso(now()), kind, 'module=privilege', `alert=${id}`, `action=${decision.action}`, `confidence=${decision.confidence}`, ...extra,
    `reason="${clean(decision.reason)}"`];
  try {
    await appendFile(logFile, `${parts.join(' ')}\n`, 'utf8');
    return true;
  } catch {
    return false;
  }
}

// decide 결과 하나를 처리합니다. block 이면 거부 규칙 시도, alert 이면 알림만, record 면 아무것도 하지 않습니다.
// 반환: { outcome: 'denied' | 'alerted' | 'recorded', rule?, skipped?, logged }
export async function respond(alert, decision, { denyList, logFile = DEFAULT_LOG, now = Date.now } = {}) {
  if (!denyList || typeof denyList.add !== 'function') throw new TypeError('invalid_deny_list');
  const action = decision?.action;
  if (action !== 'block' && action !== 'alert') return { outcome: 'recorded', logged: false };
  const safe = { action, confidence: decision.confidence, reason: decision.reason ?? '' };

  if (action === 'block') {
    const added = denyList.add(alert, safe);
    if (added.rule) {
      const logged = await writeLine(logFile, now, 'BLOCK', alert, safe,
        [`rule=${added.rule.ruleId}`, `expires=${added.rule.expiresAt}`]);
      return { outcome: 'denied', rule: added.rule, logged };
    }
    // 거두지 못한 차단 후보는 사람이 확인하도록 알립니다.
    const logged = await writeLine(logFile, now, 'ALERT', alert, safe, [`block_skipped=${added.skipped}`]);
    return { outcome: 'alerted', skipped: added.skipped, logged };
  }
  const logged = await writeLine(logFile, now, 'ALERT', alert, safe, []);
  return { outcome: 'alerted', logged };
}

// decide 를 부른 뒤 바로 respond 합니다.
export async function handleAlert(alert, options) {
  return respond(alert, decide(alert), options);
}

// 직접 실행하면 시험 경보 묶음을 시간 순서대로 다시 흘려 결과를 보여 줍니다. 경보 시각을 시계로 써서 만료까지 그대로 재현합니다.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const flag = process.argv.indexOf('--log');
    const logFile = flag > 1 && process.argv[flag + 1] ? process.argv[flag + 1] : DEFAULT_LOG;
    const fixture = JSON.parse(await readFile(fileURLToPath(new URL('../fixtures/privilege.json', import.meta.url)), 'utf8'));
    let clock = 0;
    const denyList = createDenyList({ now: () => clock });
    const counts = { denied: 0, alerted: 0, recorded: 0 };
    const ordered = [...fixture.alerts].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
    for (const alert of ordered) {
      clock = Date.parse(alert.timestamp);
      const result = await handleAlert(alert, { denyList, logFile, now: () => clock });
      counts[result.outcome] += 1;
      if (result.rule) process.stdout.write(`거둠 ${alert.id} ${result.rule.ruleId} 만료 ${result.rule.expiresAt}\n`);
    }
    process.stdout.write(`경보 ${ordered.length}건: 거부 규칙 ${counts.denied}, 알림 ${counts.alerted}, 기록만 ${counts.recorded}\n알림 로그: ${logFile}\n`);
  } catch (error) {
    process.stderr.write(`다시 흘리지 못했습니다: ${error.message}\n`);
    process.exitCode = 1;
  }
}
