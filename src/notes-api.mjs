// 서버에서만 실행됩니다. SUPABASE_URL과 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽습니다.
// 키 값은 응답·로그·오류 메시지에 절대 넣지 않습니다.
// 요청의 로그인 토큰은 틀이 준 src/verify-login.mjs로만 검사하고, 사용자 ID는 그 검사 결과만 씁니다.
// 요청 본문·쿼리·헤더의 userId, owner_id, role은 읽지도 믿지도 않습니다.
//
// 모든 읽기·추가·수정·삭제는 본인 메모로 제한합니다. 검증된 사용자 ID와 DB 행의 owner_id를 비교하고,
// 맞지 않으면 기본 거부합니다. 추가할 때 owner_id는 검증된 사용자 ID로만 저장합니다.
// DB 쪽 GRANT·RLS는 이 파일이 아니라 별도 SQL로 둡니다.
import { createHash } from 'node:crypto';
import config from '../aleph.config.json' with { type: 'json' };
import { createDeviceCheck } from './device-api.mjs';
import { createLoginVerifier } from './verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const TITLE_MAX = 100;
const BODY_MAX = 2000;
const TABLE = '/rest/v1/vault_notes';
const BACKUP_TABLE = '/rest/v1/vault_notes_backup';
const AUDIT_TABLE = '/rest/v1/vault_restore_audit';
const SHA256_HEX = /^[0-9a-f]{64}$/u;

// 10단계 내용 해시: 제목 바이트, 0x00, 내용 바이트를 이어 붙인 값의 SHA-256(소문자 16진수)입니다.
// supabase/005_backup_restore.sql의 사본 생성 예시와 같은 값이 나옵니다.
export const contentSha256 = (title, content) => createHash('sha256')
  .update(Buffer.concat([Buffer.from(title, 'utf8'), Buffer.from([0]), Buffer.from(content, 'utf8')])).digest('hex');

let verifier;
const defaultVerify = (authorization) => {
  verifier ??= createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
  return verifier(authorization);
};

const sameUser = (a, b) => typeof a === 'string' && typeof b === 'string'
  && a.length > 0 && a.toLowerCase() === b.toLowerCase();
const toNote = ({ id, title, content }) => ({ id, title, body: content });

// 권한은 한 곳에서만 판단합니다. 검증된 사용자 ID와 저장된 행의 owner_id가 같을 때만 허용합니다.
// 강사 권한은 저장된 근거가 없으므로 부여하지 않습니다. 본문·쿼리·헤더·토큰의 role 같은 값은 권한이 되지 않습니다.
function authorize(identity, row) {
  if (!row) return { allowed: false, reason: 'missing' };
  if (typeof row.owner_id !== 'string' || row.owner_id.length === 0) return { allowed: false, reason: 'no_owner' };
  return sameUser(row.owner_id, identity?.userId) ? { allowed: true, reason: 'ok' }
    : { allowed: false, reason: 'not_owner' };
}

// 거부 사유는 고정된 짧은 코드와 요청 방식만 남깁니다. 사용자 ID, 메모 ID, 토큰, 본문은 기록하지 않습니다.
const logDenied = (reason, req) => console.warn('notes: 거부', reason, req.method);

// 권한처럼 보이는 값이 요청에 실려 와도 읽지 않고, 있었다는 사실만 기록합니다.
const CLAIM_NAMES = ['role', 'roles', 'owner_id', 'userid', 'user_id', 'zone', 'resource', 'is_instructor'];
function claimedPrivilege(req, body) {
  const names = [...Object.keys(body ?? {}), ...Object.keys(req.query ?? {}), ...Object.keys(req.headers ?? {})]
    .map(name => name.toLowerCase().replace(/^x-/u, '').replace(/-/gu, '_'));
  return names.some(name => CLAIM_NAMES.includes(name));
}

function readJsonBody(req) {
  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return null; }
  }
  return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
}

function cleanFields(body) {
  if (typeof body.title !== 'string') return null;
  const title = body.title.trim();
  const text = body.body === undefined ? '' : body.body;
  if (!title || title.length > TITLE_MAX || typeof text !== 'string' || text.length > BODY_MAX) return null;
  return { title, content: text };
}

// /api/notes/:id/restore 에서는 ID가 끝에서 둘째 구간입니다.
function restorePathId(req) {
  let segments = [];
  try { segments = new URL(req.url, 'http://local').pathname.split('/').filter(Boolean); } catch { /* use query */ }
  const candidate = segments.at(-1) === 'restore' && UUID.test(segments.at(-2) ?? '') ? segments.at(-2) : req.query?.id;
  return typeof candidate === 'string' && UUID.test(candidate) ? candidate.toLowerCase() : null;
}

function pathId(req) {
  let last;
  try { last = new URL(req.url, 'http://local').pathname.split('/').filter(Boolean).at(-1); } catch { /* use query */ }
  const candidate = last && UUID.test(last) ? last : req.query?.id;
  return typeof candidate === 'string' && UUID.test(candidate) ? candidate.toLowerCase() : null;
}

// deviceCheck를 주면 승인된 기기에서 온 요청만 자료를 받습니다(11단계). 운영용 notesApi에 연결합니다.
export function createNotesApi({ verify = defaultVerify, env = process.env, fetchImpl = fetch, deviceCheck = null } = {}) {
  const store = async (method, { query = {}, body, prefer, table = TABLE } = {}) => {
    const url = new URL(table, env.SUPABASE_URL);
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

  // 공통 앞부분: 허용 방식 → 서버 설정 → 로그인 검사. 통과하면 { identity }, 아니면 응답을 이미 보낸 뒤 null.
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
      identity = await verify(req.headers.authorization);
    } catch (error) {
      // 검사기를 만들 때의 설정 오류만 여기로 옵니다. 메시지는 고정된 오류 이름입니다.
      console.error('notes: 로그인 검사기를 쓸 수 없음', error instanceof TypeError ? error.message : '알 수 없는 오류');
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

  const storeFailed = (res, status) => {
    console.error('notes: 자료 저장소가 오류 상태를 돌려줌', status);
    return res.status(502).json({ error: '자료를 불러오지 못했습니다.' });
  };
  const unreachable = (res) => {
    console.error('notes: 자료 저장소에 연결하지 못함');
    return res.status(502).json({ error: '자료를 불러오지 못했습니다.' });
  };

  // /api/notes : GET 목록, POST 추가
  const collection = async (req, res) => {
    const checked = await guard(req, res, ['GET', 'POST']);
    if (!checked) return undefined;
    const { identity } = checked;
    try {
      if (req.method === 'GET') {
        if (claimedPrivilege(req, null)) logDenied('privilege_field_ignored', req);
        const result = await store('GET', { query: {
          select: 'id,title,content,owner_id', owner_id: `eq.${identity.userId}`, order: 'created_at.asc,id.asc',
        } });
        if (!result.ok) return storeFailed(res, result.status);
        // 저장소가 조건을 지키지 않은 경우에 대비해, 돌아온 행의 소유자를 코드에서 다시 대조합니다.
        const rows = Array.isArray(result.rows) ? result.rows : [];
        const mine = rows.filter(row => authorize(identity, row).allowed);
        if (mine.length !== rows.length) logDenied('owner_mismatch', req);
        return res.status(200).json(mine.map(toNote));
      }

      const body = readJsonBody(req);
      if (claimedPrivilege(req, body)) logDenied('privilege_field_ignored', req);
      const fields = body && cleanFields(body);
      if (!fields) return res.status(400).json({ error: '제목(1~100자)과 내용(2000자 이하)을 문자열로 보내 주세요.' });
      if (body.id !== undefined && !(typeof body.id === 'string' && UUID.test(body.id))) {
        return res.status(400).json({ error: 'id는 UUID여야 합니다.' });
      }
      const row = { ...fields, owner_id: identity.userId };
      if (body.id !== undefined) row.id = body.id.toLowerCase();
      const result = await store('POST', { query: { select: 'id' }, body: row, prefer: 'return=representation' });
      if (result.status === 409) return res.status(409).json({ error: '이미 있는 id입니다.' });
      if (!result.ok || !Array.isArray(result.rows) || !result.rows[0]?.id) return storeFailed(res, result.status);
      return res.status(201).json({ id: result.rows[0].id });
    } catch {
      return unreachable(res);
    }
  };

  // 검증된 사용자 ID와 DB 행의 owner_id를 코드에서 직접 비교합니다.
  // 남의 메모, 주인이 없는 메모, 없는 메모는 모두 같은 404로 답해 존재 여부를 알려 주지 않습니다.
  const loadOwned = async (id, identity) => {
    const result = await store('GET', { query: { select: 'id,title,content,owner_id', id: `eq.${id}`, limit: '1' } });
    if (!result.ok) return { failed: result.status };
    const row = result.rows?.[0];
    const verdict = authorize(identity, row);
    return verdict.allowed ? { row } : { missing: true, reason: verdict.reason };
  };

  // /api/notes/:id : GET 한 건, PUT 수정, DELETE 삭제 (모두 본인 메모만)
  const item = async (req, res) => {
    const checked = await guard(req, res, ['GET', 'PUT', 'DELETE']);
    if (!checked) return undefined;
    const { identity } = checked;
    const id = pathId(req);
    const notFound = (reason = 'missing') => {
      logDenied(reason, req);
      return res.status(404).json({ error: '메모를 찾을 수 없습니다.' });
    };
    if (!id) return notFound('bad_id');
    try {
      if (req.method === 'PUT') {
        const body = readJsonBody(req);
        if (claimedPrivilege(req, body)) logDenied('privilege_field_ignored', req);
        const fields = body && cleanFields(body);
        if (!fields) return res.status(400).json({ error: '제목(1~100자)과 내용(2000자 이하)을 문자열로 보내 주세요.' });
        if (body.id !== undefined && String(body.id).toLowerCase() !== id) {
          return res.status(400).json({ error: '본문의 id가 경로의 id와 다릅니다.' });
        }
        // 새 행의 소유자도 본인이어야 합니다. 본문이 다른 owner_id를 내세우면 쓰기 전에 거부합니다.
        if ('owner_id' in body && !(typeof body.owner_id === 'string' && sameUser(body.owner_id, identity.userId))) {
          logDenied('owner_change_attempt', req);
          return res.status(403).json({ error: '메모의 소유자는 바꿀 수 없습니다.' });
        }
        const owned = await loadOwned(id, identity);
        if (owned.failed) return storeFailed(res, owned.failed);
        if (owned.missing) return notFound(owned.reason);
        // 조건에 owner_id를 다시 걸어, 확인과 쓰기 사이에 소유자가 바뀐 경우에도 본인 행만 고칩니다.
        const result = await store('PATCH', {
          query: { select: 'id', id: `eq.${id}`, owner_id: `eq.${identity.userId}` },
          body: { ...fields, owner_id: identity.userId }, prefer: 'return=representation',
        });
        if (!result.ok) return storeFailed(res, result.status);
        return result.rows?.[0] ? res.status(200).json({ id }) : notFound('owner_changed');
      }

      if (claimedPrivilege(req, null)) logDenied('privilege_field_ignored', req);
      const owned = await loadOwned(id, identity);
      if (owned.failed) return storeFailed(res, owned.failed);
      if (owned.missing) return notFound(owned.reason);
      if (req.method === 'GET') return res.status(200).json(toNote(owned.row));

      const result = await store('DELETE', {
        query: { select: 'id', id: `eq.${id}`, owner_id: `eq.${identity.userId}` }, prefer: 'return=representation',
      });
      if (!result.ok) return storeFailed(res, result.status);
      return result.rows?.[0] ? res.status(200).json({ id }) : notFound('owner_changed');
    } catch {
      return unreachable(res);
    }
  };

  // 10단계 POST /api/notes/:id/restore : 비공개 사본에서 지정한 한 건만 되살립니다.
  // 사본의 ID·소유자·내용 해시를 요청의 해시와 대조하고, 본인 사본·본인 메모에만 씁니다.
  // 다른 메모는 건드리지 않고, 복원마다 감사 표에 한 줄을 덧붙입니다. 감사 기록이 실패하면 복원도 되돌립니다.
  // 응답과 로그에는 메모 내용, 해시 원문, 토큰을 싣지 않습니다.
  const restore = async (req, res) => {
    const checked = await guard(req, res, ['POST']);
    if (!checked) return undefined;
    const { identity } = checked;
    const notFound = (reason) => {
      logDenied(reason, req);
      return res.status(404).json({ error: '복원할 사본을 찾을 수 없습니다.' });
    };
    const conflict = (reason) => {
      logDenied(reason, req);
      return res.status(409).json({ error: '사본의 내용 해시가 맞지 않아 복원하지 않았습니다.' });
    };
    const id = restorePathId(req);
    if (!id) return notFound('bad_id');
    const body = readJsonBody(req);
    if (claimedPrivilege(req, body)) logDenied('privilege_field_ignored', req);
    const expected = body?.contentSha256;
    if (typeof expected !== 'string' || !SHA256_HEX.test(expected)) {
      return res.status(400).json({ error: 'contentSha256(소문자 16진수 64자)를 문자열로 보내 주세요.' });
    }
    const target = { select: 'id,title,content,owner_id', id: `eq.${id}`, limit: '1' };
    let undo = null;
    try {
      const saved = await store('GET', { table: BACKUP_TABLE, query: { select: 'id,owner_id,title,content,content_sha256', id: `eq.${id}`, limit: '1' } });
      if (!saved.ok) return storeFailed(res, saved.status);
      const backup = saved.rows?.[0];
      const verdict = authorize(identity, backup);
      if (!verdict.allowed) return notFound(`backup_${verdict.reason}`);
      if (String(backup.id).toLowerCase() !== id || typeof backup.title !== 'string' || typeof backup.content !== 'string'
          || contentSha256(backup.title, backup.content) !== backup.content_sha256) return conflict('backup_invalid');
      if (backup.content_sha256 !== expected) return conflict('hash_mismatch');

      const current = await store('GET', { query: target });
      if (!current.ok) return storeFailed(res, current.status);
      const row = current.rows?.[0];
      if (row && !authorize(identity, row).allowed) return notFound('target_not_owned');

      let written;
      if (row) {
        undo = async () => store('PATCH', { query: { id: `eq.${id}`, owner_id: `eq.${identity.userId}` }, body: { title: row.title, content: row.content } });
        written = await store('PATCH', { query: { select: 'id', id: `eq.${id}`, owner_id: `eq.${identity.userId}` },
          body: { title: backup.title, content: backup.content }, prefer: 'return=representation' });
      } else {
        undo = async () => store('DELETE', { query: { id: `eq.${id}`, owner_id: `eq.${identity.userId}` } });
        written = await store('POST', { query: { select: 'id' }, prefer: 'return=representation',
          body: { id, owner_id: identity.userId, title: backup.title, content: backup.content } });
      }
      if (written.status === 409) { undo = null; return conflict('target_conflict'); }
      if (!written.ok || !written.rows?.[0]) { undo = null; return row ? notFound('owner_changed') : storeFailed(res, written.status); }

      // 쓴 뒤 다시 읽어 ID·소유자·내용 해시가 사본과 같은지 확인합니다. 다르면 이전 상태로 되돌립니다.
      const after = await store('GET', { query: target });
      const now = after.rows?.[0];
      const same = after.ok && now && String(now.id).toLowerCase() === id && authorize(identity, now).allowed
        && typeof now.title === 'string' && typeof now.content === 'string'
        && contentSha256(now.title, now.content) === backup.content_sha256;
      if (!same) throw new Error('verify_failed');

      const audit = await store('POST', { table: AUDIT_TABLE, prefer: 'return=minimal',
        body: { note_id: id, owner_id: identity.userId, content_sha256: backup.content_sha256, outcome: 'restored' } });
      if (!audit.ok) throw new Error('audit_failed');
      undo = null;
      return res.status(200).json({ id, restored: true, contentSha256: backup.content_sha256 });
    } catch (error) {
      if (undo) { try { await undo(); } catch { console.error('notes: 복원을 되돌리지 못함'); } }
      console.error('notes: 복원 실패', error?.message === 'verify_failed' || error?.message === 'audit_failed' ? error.message : '저장소 오류');
      return res.status(500).json({ error: '복원하지 못했습니다. 이전 상태를 유지했습니다.' });
    }
  };

  return { collection, item, restore, gated: Boolean(deviceCheck) };
}

export const notesApi = createNotesApi({ deviceCheck: createDeviceCheck() });
