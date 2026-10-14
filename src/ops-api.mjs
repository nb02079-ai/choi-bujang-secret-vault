// 서버에서만 실행됩니다. 탈환 작전실이 읽는 요약을 만듭니다. 읽기 전용이며 어떤 표에도 쓰지 않습니다.
// SUPABASE_URL과 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽고, 키·토큰·쿠키 값은 응답·로그에 싣지 않습니다.
//
// 응답에 들어가는 수치는 이 요청에서 실제로 읽은 값뿐입니다. 읽지 못한 구역은 confirmed:false로 알리고,
// 기록이 남지 않는 판정 결과와 탐지 사건, 심판이 확인하는 실제 회수 집행은 미기록·미실행으로 따로 적습니다.
// 본인(로그인한 계정)의 기록만 읽습니다. 메모 제목·내용, 쿠키 값, 해시 원문, 승인 코드, 소유자 번호, 전체 UUID는 싣지 않습니다.
import { createHash } from 'node:crypto';
import config from '../aleph.config.json' with { type: 'json' };
import { describePolicy } from './decider.mjs';
import { DETECTION_RULE } from './detect.mjs';
import { createDeviceCheck } from './device-api.mjs';
import { canonical } from './policy-diff.mjs';
import { createLoginVerifier } from './verify-login.mjs';

export const OPS_SCHEMA = 'vault.ops.summary.v1';
export const RECORD_LIMIT = 10;
export const FETCH_LIMIT = 100;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const SHA256 = /^[0-9a-f]{64}$/u;
const DEVICE_STATES = ['pending', 'approved', 'denied', 'revoked'];

let verifier;
const defaultVerify = (authorization) => {
  verifier ??= createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
  return verifier(authorization);
};

const logDenied = (reason, req) => console.warn('ops: 거부', reason, req.method);
const ref = (value) => (typeof value === 'string' && UUID.test(value) ? value.slice(0, 8).toLowerCase() : null);
const hash12 = (value) => (typeof value === 'string' && SHA256.test(value) ? value.slice(0, 12) : null);
const iso = (value) => (typeof value === 'string' && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null);
const newestFirst = (field) => (a, b) => (Date.parse(b[field]) || 0) - (Date.parse(a[field]) || 0);

// 표에서 본인 행만 읽기 전용으로 가져옵니다. 오류나 형식 문제는 null이며 그 구역만 미확인이 됩니다.
function createReader(env, fetchImpl) {
  return async (table, query) => {
    try {
      const url = new URL(`/rest/v1/${table}`, env.SUPABASE_URL);
      for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
      const upstream = await fetchImpl(url, {
        method: 'GET', headers: { apikey: env.SUPABASE_SECRET_KEY, Accept: 'application/json' },
        redirect: 'error', signal: AbortSignal.timeout(8000),
      });
      if (!upstream.ok) return null;
      const rows = await upstream.json();
      return Array.isArray(rows) ? rows : null;
    } catch {
      return null;
    }
  };
}

const unconfirmed = (source) => ({ confirmed: false, source, reason: '이번 요청에서 읽지 못했습니다.' });
const listed = (rows, shape, field) => {
  const items = rows.map(shape).sort(newestFirst(field));
  return { total: rows.length, truncated: rows.length >= FETCH_LIMIT, records: items.slice(0, RECORD_LIMIT) };
};

export function createOpsApi({ verify = defaultVerify, env = process.env, fetchImpl = fetch, now = Date.now, deviceCheck = null } = {}) {
  const read = createReader(env, fetchImpl);

  // 허용 방식 → 서버 설정 → 로그인 검사 → 기기 승인 검사. 통과하면 { identity }, 아니면 응답을 보낸 뒤 null.
  const guard = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      res.status(405).json({ error: '허용되지 않는 요청입니다.' });
      return null;
    }
    if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY) {
      res.status(500).json({ error: '서버 설정이 아직 끝나지 않았습니다.' });
      return null;
    }
    let identity;
    try {
      identity = await verify(req.headers?.authorization);
    } catch (error) {
      console.error('ops: 로그인 검사기를 쓸 수 없음', error instanceof TypeError ? error.message : '알 수 없는 오류');
      res.status(500).json({ error: '서버 설정이 아직 끝나지 않았습니다.' });
      return null;
    }
    if (!identity || !UUID.test(identity.userId ?? '')) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      res.status(401).json({ error: '로그인이 필요합니다.' });
      return null;
    }
    if (deviceCheck) {
      let verdict;
      try { verdict = await deviceCheck(req, identity); } catch { verdict = { allowed: false, reason: 'device_check_failed' }; }
      if (!verdict?.allowed) {
        logDenied(verdict?.reason ?? 'device_check_failed', req);
        res.status(403).json({ error: '기기 승인이 필요합니다.', code: 'device_not_approved' });
        return null;
      }
    }
    return { identity };
  };

  const summary = async (req, res) => {
    const checked = await guard(req, res);
    if (!checked) return undefined;
    const owner = `eq.${checked.identity.userId}`;
    const nowMs = now();

    const policy = { ...describePolicy(), allowedRoutes: [...config.allowedRoutes] };
    const decider = {
      confirmed: true, source: 'code', ruleIds: policy.ruleIds, ruleCount: policy.ruleIds.length,
      zoneRouteCount: Object.values(policy.zoneRoutes).reduce((sum, list) => sum + list.length, 0),
      allowedRouteCount: policy.allowedRoutes.length,
      policyDigest: createHash('sha256').update(canonical(policy)).digest('hex').slice(0, 12),
      results: { recorded: false, reason: '판정기는 판정 결과를 저장하지 않아 집계할 수 없습니다.' },
    };
    const detection = {
      confirmed: true, source: 'code', rule: { ...DETECTION_RULE },
      events: { recorded: false, reason: '탐지 사건을 남기는 저장소가 없어 사건 수를 알 수 없습니다.' },
    };

    const [deviceRows, backupRows, auditRows] = await Promise.all([
      read('vault_devices', { select: 'id,status,created_at,decided_at,expires_at', owner_id: owner, order: 'created_at.desc', limit: String(FETCH_LIMIT) }),
      read('vault_notes_backup', { select: 'id,content_sha256,backed_up_at', owner_id: owner, order: 'backed_up_at.desc', limit: String(FETCH_LIMIT) }),
      read('vault_restore_audit', { select: 'id,note_id,content_sha256,outcome,restored_at', owner_id: owner, order: 'restored_at.desc', limit: String(FETCH_LIMIT) }),
    ]);

    let revocation = { ...unconfirmed('vault_devices') };
    if (deviceRows) {
      const counts = { pending: 0, expired: 0, approved: 0, denied: 0, revoked: 0, other: 0 };
      const state = (row) => {
        if (row.status === 'pending') return Date.parse(row.expires_at) > nowMs ? 'pending' : 'expired';
        return DEVICE_STATES.includes(row.status) ? row.status : 'other';
      };
      for (const row of deviceRows) counts[state(row)] += 1;
      revocation = {
        confirmed: true, source: 'vault_devices', counts,
        ...listed(deviceRows, (row) => ({ ref: ref(row.id), status: state(row), createdAt: iso(row.created_at), decidedAt: iso(row.decided_at) }), 'createdAt'),
        enforcement: { run: false, reason: 'propose_revocation 제안의 실제 집행은 심판이 확인하므로 이 화면에서 확인할 수 없습니다.' },
      };
    } else {
      revocation.enforcement = { run: false, reason: 'propose_revocation 제안의 실제 집행은 심판이 확인하므로 이 화면에서 확인할 수 없습니다.' };
    }

    const backups = backupRows
      ? { confirmed: true, source: 'vault_notes_backup', ...listed(backupRows, (row) => ({ ref: ref(row.id), hash12: hash12(row.content_sha256), at: iso(row.backed_up_at) }), 'at') }
      : unconfirmed('vault_notes_backup');
    const restores = auditRows
      ? {
        confirmed: true, source: 'vault_restore_audit',
        ...listed(auditRows, (row) => ({
          ref: ref(row.note_id), hash12: hash12(row.content_sha256), at: iso(row.restored_at),
          outcome: typeof row.outcome === 'string' && /^[a-z_]{1,20}$/u.test(row.outcome) ? row.outcome : 'other',
        }), 'at'),
      }
      : unconfirmed('vault_restore_audit');
    const recovery = {
      confirmed: Boolean(backupRows || auditRows), source: 'vault_notes_backup+vault_restore_audit', backups, restores,
      policySnapshot: { confirmed: false, reason: '정책 사본은 로컬 파일이라 서버가 버전을 읽을 수 없습니다.' },
    };

    return res.status(200).json({
      schema: OPS_SCHEMA, readAt: new Date(nowMs).toISOString(), decider, detection, revocation, recovery,
      notRun: [
        { id: 'decision_results', text: '판정 결과(allow·deny 집계)는 기록이 없어 확인하지 못했습니다.' },
        { id: 'detection_events', text: '탐지 사건은 기록이 없어 확인하지 못했습니다.' },
        { id: 'revocation_enforcement', text: '실제 회수 집행과 걸린 시간은 심판이 확인하므로 미실행입니다.' },
        { id: 'policy_snapshot', text: '정책 사본 버전은 서버가 읽을 수 없어 미확인입니다.' },
        { id: 'attack_verdict', text: '41종 공격 방어 여부는 심판이 판정하며 이 화면은 통과 근거가 아닙니다.' },
      ],
    });
  };

  return { summary, gated: Boolean(deviceCheck) };
}

// 운영용은 승인된 기기에서 온 요청만 받습니다. 시험용 createOpsApi()는 deviceCheck를 직접 줘야 검사합니다.
export const opsApi = createOpsApi({ deviceCheck: createDeviceCheck() });
