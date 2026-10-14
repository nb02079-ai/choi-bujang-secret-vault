// 서버에서만 실행됩니다. SUPABASE_URL과 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽습니다.
// 11단계 기기 승인: 기기를 알아보는 값은 서버가 만든 HttpOnly 쿠키로만 내려 주고, 화면의 스크립트는 읽지 못합니다.
// DB(vault_devices)에는 쿠키 값의 SHA-256 해시만 저장합니다. 쿠키 값, 해시, 로그인 토큰은 응답·로그·오류 메시지에 싣지 않습니다.
//
// 승인은 버튼으로 정해지지 않고 서버가 정합니다.
// - 새 기기의 요청은 '승인 대기' 기록과 승인 코드만 만들고 권한을 주지 않습니다.
// - 승인은 이미 승인된 기기에서, 같은 계정으로 로그인한 상태로, 유효한 코드를 보낼 때만 됩니다.
// - 첫 기기는 승인된 기기가 없으므로 운영자가 DB에서 직접 승인합니다(README의 순서).
// 요청 본문·쿼리·헤더의 userId, owner_id, role, device 값은 읽지도 믿지도 않습니다.
import { createHash, randomBytes as nodeRandomBytes } from 'node:crypto';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from './verify-login.mjs';

export const DEVICE_COOKIE = '__Host-vault_device';
export const REQUEST_TTL_SECONDS = 900;
const TABLE = '/rest/v1/vault_devices';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const COOKIE_VALUE = /^[A-Za-z0-9_-]{43}$/u;
const CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const CODE_PATTERN = /^[0-9A-HJKMNP-TV-Z]{8}$/u;
const MAX_PENDING = 5;
const COOKIE_MAX_AGE_SECONDS = 90 * 24 * 60 * 60;

let verifier;
const defaultVerify = (authorization) => {
  verifier ??= createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
  return verifier(authorization);
};

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const sameUser = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length > 0 && a.toLowerCase() === b.toLowerCase();
const logDenied = (reason, req) => console.warn('device: 거부', reason, req.method);
const CLAIM_NAMES = ['role', 'roles', 'owner_id', 'userid', 'user_id', 'device', 'device_id', 'status', 'is_instructor'];

function readJsonBody(req) {
  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return null; }
  }
  return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
}

// Cookie 헤더에서 우리 기기 쿠키 값만 꺼냅니다. 형식이 맞지 않으면 없는 것으로 봅니다.
export function readDeviceCookie(req) {
  const header = req?.headers?.cookie;
  if (typeof header !== 'string' || header.length > 4096) return null;
  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === DEVICE_COOKIE) {
      const value = rest.join('=');
      return COOKIE_VALUE.test(value) ? value : null;
    }
  }
  return null;
}

const cookieHeader = (value) => `${DEVICE_COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${COOKIE_MAX_AGE_SECONDS}`;

function createStore(env, fetchImpl) {
  return async (method, { query = {}, body, prefer } = {}) => {
    const url = new URL(TABLE, env.SUPABASE_URL);
    for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
    const headers = { apikey: env.SUPABASE_SECRET_KEY, Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (prefer) headers.Prefer = prefer;
    const upstream = await fetchImpl(url, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'error', signal: AbortSignal.timeout(8000),
    });
    let rows = null;
    if (upstream.ok) { try { rows = await upstream.json(); } catch { rows = null; } }
    return { status: upstream.status, ok: upstream.ok, rows };
  };
}

// 화면에 알리는 상태는 네 가지뿐입니다. 알 수 없는 상태는 모두 거부됨으로 닫습니다.
function publicStatus(row, nowMs) {
  if (row.status === 'approved') return 'approved';
  if (row.status === 'pending') return Date.parse(row.expires_at) > nowMs ? 'pending' : 'unverified';
  return 'denied';
}

async function lookup(store, cookieValue, userId) {
  const result = await store('GET', { query: {
    select: 'id,owner_id,status,request_code,expires_at', secret_sha256: `eq.${sha256(cookieValue)}`, limit: '1',
  } });
  if (!result.ok) return { failed: true };
  const row = result.rows?.[0];
  return row && sameUser(row.owner_id, userId) ? { row } : {};
}

// 자료 API가 쓰는 기기 검사입니다. 승인된 기기에서 온 학생 요청만 통과시키고, 확인하지 못하면 닫습니다.
// judge 종류의 토큰은 기기 검증을 엔진이 맡는다고 보고 통과시킵니다(확인하지 못한 가정). DEVICE_GATE=off이면 끕니다.
export function createDeviceCheck({ env = process.env, fetchImpl = fetch, now = Date.now } = {}) {
  const store = createStore(env, fetchImpl);
  return async (req, identity) => {
    if (env.DEVICE_GATE === 'off') return { allowed: true, reason: 'gate_off' };
    if (identity?.kind === 'judge') return { allowed: true, reason: 'judge' };
    const cookie = readDeviceCookie(req);
    if (!cookie) return { allowed: false, reason: 'no_device' };
    if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY) return { allowed: false, reason: 'device_store_unset' };
    try {
      const found = await lookup(store, cookie, identity?.userId);
      if (found.failed) return { allowed: false, reason: 'device_lookup_failed' };
      if (!found.row) return { allowed: false, reason: 'device_unknown' };
      const status = publicStatus(found.row, now());
      return status === 'approved' ? { allowed: true, reason: 'approved' } : { allowed: false, reason: `device_${status}` };
    } catch {
      return { allowed: false, reason: 'device_lookup_failed' };
    }
  };
}

export function createDeviceApi({ verify = defaultVerify, env = process.env, fetchImpl = fetch, now = Date.now, randomBytes = nodeRandomBytes } = {}) {
  const store = createStore(env, fetchImpl);
  const makeCode = () => Array.from(randomBytes(8), (byte) => CODE_ALPHABET[byte % CODE_ALPHABET.length]).join('');
  const expiresAt = () => new Date(now() + REQUEST_TTL_SECONDS * 1000).toISOString();
  const pendingBody = (row) => ({
    status: 'pending', code: row.request_code,
    expiresInSeconds: Math.max(0, Math.floor((Date.parse(row.expires_at) - now()) / 1000)),
  });

  // 허용 방식 → 서버 설정 → 로그인 검사. 통과하면 { identity }, 아니면 응답을 이미 보낸 뒤 null.
  const guard = async (req, res, allowed) => {
    res.setHeader('Cache-Control', 'no-store');
    if (!allowed.includes(req.method)) {
      res.setHeader('Allow', allowed.join(', '));
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
      console.error('device: 로그인 검사기를 쓸 수 없음', error instanceof TypeError ? error.message : '알 수 없는 오류');
      res.status(500).json({ error: '서버 설정이 아직 끝나지 않았습니다.' });
      return null;
    }
    if (!identity || !UUID.test(identity.userId ?? '')) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      res.status(401).json({ error: '로그인이 필요합니다.' });
      return null;
    }
    return { identity };
  };
  const storeFailed = (res) => {
    console.error('device: 기기 저장소가 오류 상태를 돌려줌');
    return res.status(502).json({ error: '기기 상태를 확인하지 못했습니다.' });
  };
  const unreachable = (res) => {
    console.error('device: 기기 저장소에 연결하지 못함');
    return res.status(502).json({ error: '기기 상태를 확인하지 못했습니다.' });
  };
  const noteClaims = (req, body) => {
    const names = [...Object.keys(body ?? {}), ...Object.keys(req.query ?? {}), ...Object.keys(req.headers ?? {})]
      .map((name) => name.toLowerCase().replace(/^x-/u, '').replace(/-/gu, '_'));
    if (names.some((name) => CLAIM_NAMES.includes(name))) logDenied('privilege_field_ignored', req);
  };

  // GET /api/device/status : 이 기기의 승인 상태. 쿠키가 없거나 모르는 기기이면 unverified입니다.
  const status = async (req, res) => {
    const checked = await guard(req, res, ['GET']);
    if (!checked) return undefined;
    noteClaims(req, null);
    const cookie = readDeviceCookie(req);
    if (!cookie) return res.status(200).json({ status: 'unverified' });
    try {
      const found = await lookup(store, cookie, checked.identity.userId);
      if (found.failed) return storeFailed(res);
      if (!found.row) return res.status(200).json({ status: 'unverified' });
      const current = publicStatus(found.row, now());
      return res.status(200).json(current === 'pending' ? pendingBody(found.row) : { status: current });
    } catch {
      return unreachable(res);
    }
  };

  // POST /api/device/request : 승인 요청. 대기 기록과 승인 코드만 만들며 권한은 주지 않습니다.
  const request = async (req, res) => {
    const checked = await guard(req, res, ['POST']);
    if (!checked) return undefined;
    const { identity } = checked;
    noteClaims(req, readJsonBody(req));
    try {
      const cookie = readDeviceCookie(req);
      const found = cookie ? await lookup(store, cookie, identity.userId) : {};
      if (found.failed) return storeFailed(res);
      if (found.row) {
        const current = publicStatus(found.row, now());
        if (current === 'approved') return res.status(200).json({ status: current });
        if (current === 'denied') {
          logDenied('device_denied', req);
          return res.status(403).json({ status: current, error: '이 기기는 승인되지 않았습니다. 운영자에게 문의해 주세요.' });
        }
        if (current === 'pending') return res.status(200).json(pendingBody(found.row));
        // 만료된 요청은 같은 기기 쿠키로 새 코드를 발급합니다.
        const fresh = { request_code: makeCode(), expires_at: expiresAt() };
        const patched = await store('PATCH', {
          query: { select: 'id', id: `eq.${found.row.id}`, owner_id: `eq.${identity.userId}`, status: 'eq.pending' },
          body: fresh, prefer: 'return=representation',
        });
        if (!patched.ok || !patched.rows?.[0]) return storeFailed(res);
        return res.status(200).json(pendingBody(fresh));
      }

      const open = await store('GET', { query: { select: 'id,request_code,expires_at', owner_id: `eq.${identity.userId}`, status: 'eq.pending' } });
      if (!open.ok) return storeFailed(res);
      const active = (open.rows ?? []).filter((row) => Date.parse(row.expires_at) > now());
      if (active.length >= MAX_PENDING) {
        logDenied('too_many_pending', req);
        return res.status(429).json({ error: '승인 요청이 너무 많습니다. 승인되거나 만료된 뒤에 다시 시도해 주세요.' });
      }
      let code = makeCode();
      while (active.some((row) => row.request_code === code)) code = makeCode();
      const secret = randomBytes(32).toString('base64url');
      const row = { owner_id: identity.userId, secret_sha256: sha256(secret), status: 'pending', request_code: code, expires_at: expiresAt() };
      const created = await store('POST', { query: { select: 'id' }, body: row, prefer: 'return=representation' });
      if (!created.ok || !created.rows?.[0]?.id) return storeFailed(res);
      res.setHeader('Set-Cookie', cookieHeader(secret));
      return res.status(201).json(pendingBody(row));
    } catch {
      return unreachable(res);
    }
  };

  // POST /api/device/approve {code} : 승인된 기기에서 같은 계정의 대기 중인 요청 하나를 승인합니다.
  const approve = async (req, res) => {
    const checked = await guard(req, res, ['POST']);
    if (!checked) return undefined;
    const { identity } = checked;
    const body = readJsonBody(req);
    noteClaims(req, body);
    const notFound = (reason) => {
      logDenied(reason, req);
      return res.status(404).json({ error: '승인할 요청을 찾을 수 없습니다.' });
    };
    try {
      const cookie = readDeviceCookie(req);
      const caller = cookie ? await lookup(store, cookie, identity.userId) : {};
      if (caller.failed) return storeFailed(res);
      if (!caller.row || publicStatus(caller.row, now()) !== 'approved') {
        logDenied('caller_not_approved', req);
        return res.status(403).json({ error: '이미 승인된 기기에서만 다른 기기를 승인할 수 있습니다.' });
      }
      const code = typeof body?.code === 'string' ? body.code.replace(/[\s-]/gu, '').toUpperCase() : '';
      if (!CODE_PATTERN.test(code)) return res.status(400).json({ error: '승인 코드는 영문 대문자와 숫자 8자입니다.' });
      const target = await store('GET', { query: {
        select: 'id,expires_at', owner_id: `eq.${identity.userId}`, status: 'eq.pending', request_code: `eq.${code}`, limit: '1',
      } });
      if (!target.ok) return storeFailed(res);
      const pending = target.rows?.[0];
      if (!pending) return notFound('code_unknown');
      if (Date.parse(pending.expires_at) <= now()) return notFound('code_expired');
      const decided = await store('PATCH', {
        query: { select: 'id', id: `eq.${pending.id}`, owner_id: `eq.${identity.userId}`, status: 'eq.pending' },
        body: { status: 'approved', decided_at: new Date(now()).toISOString(), decided_by: `device:${caller.row.id}` },
        prefer: 'return=representation',
      });
      if (!decided.ok) return storeFailed(res);
      return decided.rows?.[0] ? res.status(200).json({ approved: true }) : notFound('code_used');
    } catch {
      return unreachable(res);
    }
  };

  return { status, request, approve };
}

export const deviceApi = createDeviceApi();
