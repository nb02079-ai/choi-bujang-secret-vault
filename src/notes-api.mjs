// 서버에서만 실행됩니다. SUPABASE_URL과 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽습니다.
// 키 값은 응답·로그·오류 메시지에 절대 넣지 않습니다.
// 요청의 로그인 토큰은 틀이 준 src/verify-login.mjs로만 검사하고, 사용자 ID는 그 검사 결과만 씁니다.
// 요청 본문·쿼리·헤더의 userId, owner_id, role은 읽지도 믿지도 않습니다.
//
// 모든 읽기·추가·수정·삭제는 본인 메모로 제한합니다. 검증된 사용자 ID와 DB 행의 owner_id를 비교하고,
// 맞지 않으면 기본 거부합니다. 추가할 때 owner_id는 검증된 사용자 ID로만 저장합니다.
// DB 쪽 GRANT·RLS는 이 파일이 아니라 별도 SQL로 둡니다.
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from './verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const TITLE_MAX = 100;
const BODY_MAX = 2000;
const TABLE = '/rest/v1/vault_notes';

let verifier;
const defaultVerify = (authorization) => {
  verifier ??= createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
  return verifier(authorization);
};

const sameUser = (a, b) => typeof a === 'string' && typeof b === 'string'
  && a.length > 0 && a.toLowerCase() === b.toLowerCase();
const toNote = ({ id, title, content }) => ({ id, title, body: content });

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

function pathId(req) {
  let last;
  try { last = new URL(req.url, 'http://local').pathname.split('/').filter(Boolean).at(-1); } catch { /* use query */ }
  const candidate = last && UUID.test(last) ? last : req.query?.id;
  return typeof candidate === 'string' && UUID.test(candidate) ? candidate.toLowerCase() : null;
}

export function createNotesApi({ verify = defaultVerify, env = process.env, fetchImpl = fetch } = {}) {
  const store = async (method, { query = {}, body, prefer } = {}) => {
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
        const result = await store('GET', { query: {
          select: 'id,title,content', owner_id: `eq.${identity.userId}`, order: 'created_at.asc,id.asc',
        } });
        if (!result.ok) return storeFailed(res, result.status);
        return res.status(200).json(Array.isArray(result.rows) ? result.rows.map(toNote) : []);
      }

      const body = readJsonBody(req);
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
  const loadOwned = async (id, userId) => {
    const result = await store('GET', { query: { select: 'id,title,content,owner_id', id: `eq.${id}`, limit: '1' } });
    if (!result.ok) return { failed: result.status };
    const row = result.rows?.[0];
    return row && sameUser(row.owner_id, userId) ? { row } : { missing: true };
  };

  // /api/notes/:id : GET 한 건, PUT 수정, DELETE 삭제 (모두 본인 메모만)
  const item = async (req, res) => {
    const checked = await guard(req, res, ['GET', 'PUT', 'DELETE']);
    if (!checked) return undefined;
    const { identity } = checked;
    const id = pathId(req);
    const notFound = () => res.status(404).json({ error: '메모를 찾을 수 없습니다.' });
    if (!id) return notFound();
    try {
      if (req.method === 'PUT') {
        const body = readJsonBody(req);
        const fields = body && cleanFields(body);
        if (!fields) return res.status(400).json({ error: '제목(1~100자)과 내용(2000자 이하)을 문자열로 보내 주세요.' });
        if (body.id !== undefined && String(body.id).toLowerCase() !== id) {
          return res.status(400).json({ error: '본문의 id가 경로의 id와 다릅니다.' });
        }
        // 새 행의 소유자도 본인이어야 합니다. 본문이 다른 owner_id를 내세우면 쓰기 전에 거부합니다.
        if ('owner_id' in body && !(typeof body.owner_id === 'string' && sameUser(body.owner_id, identity.userId))) {
          return res.status(403).json({ error: '메모의 소유자는 바꿀 수 없습니다.' });
        }
        const owned = await loadOwned(id, identity.userId);
        if (owned.failed) return storeFailed(res, owned.failed);
        if (owned.missing) return notFound();
        // 조건에 owner_id를 다시 걸어, 확인과 쓰기 사이에 소유자가 바뀐 경우에도 본인 행만 고칩니다.
        const result = await store('PATCH', {
          query: { select: 'id', id: `eq.${id}`, owner_id: `eq.${identity.userId}` },
          body: { ...fields, owner_id: identity.userId }, prefer: 'return=representation',
        });
        if (!result.ok) return storeFailed(res, result.status);
        return result.rows?.[0] ? res.status(200).json({ id }) : notFound();
      }

      const owned = await loadOwned(id, identity.userId);
      if (owned.failed) return storeFailed(res, owned.failed);
      if (owned.missing) return notFound();
      if (req.method === 'GET') return res.status(200).json(toNote(owned.row));

      const result = await store('DELETE', {
        query: { select: 'id', id: `eq.${id}`, owner_id: `eq.${identity.userId}` }, prefer: 'return=representation',
      });
      if (!result.ok) return storeFailed(res, result.status);
      return result.rows?.[0] ? res.status(200).json({ id }) : notFound();
    } catch {
      return unreachable(res);
    }
  };

  return { collection, item };
}

export const notesApi = createNotesApi();
