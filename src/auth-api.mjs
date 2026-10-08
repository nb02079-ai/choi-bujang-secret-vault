// 서버에서만 실행됩니다. 로그인·토큰 갱신·로그아웃을 서버 함수가 Supabase Auth로 대신 전달합니다.
// 화면 코드에는 Supabase 주소도 공개 키도 두지 않습니다. 키는 Vercel 환경변수 SUPABASE_PUBLISHABLE_KEY에서만 읽습니다.
// 이메일·비밀번호·토큰은 로그와 오류 메시지에 넣지 않습니다. 응답에는 필요한 네 값만 골라 돌려줍니다.
const EMAIL_MAX = 254;
const PASSWORD_MAX = 256;
const TOKEN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u;
const REFRESH_TOKEN = /^[A-Za-z0-9_-]{4,512}$/u;

const text = (value, max) => typeof value === 'string' && value.length > 0 && value.length <= max;

function readJsonBody(req) {
  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return null; }
  }
  return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
}

function toSession(result) {
  const accessToken = result?.access_token;
  const refreshToken = result?.refresh_token;
  const expiresAt = Number.isFinite(result?.expires_at) ? result.expires_at
    : Number.isFinite(result?.expires_in) ? Math.floor(Date.now() / 1000) + result.expires_in : null;
  if (typeof accessToken !== 'string' || !TOKEN.test(accessToken) || typeof refreshToken !== 'string'
      || !REFRESH_TOKEN.test(refreshToken) || expiresAt === null) return null;
  return { access_token: accessToken, refresh_token: refreshToken, expires_at: expiresAt,
    email: typeof result.user?.email === 'string' ? result.user.email : '' };
}

export function createAuthApi({ env = process.env, fetchImpl = fetch } = {}) {
  const upstream = async (path, { query, body, token } = {}) => {
    const url = new URL(`/auth/v1/${path}`, env.SUPABASE_URL);
    if (query) url.search = query;
    const headers = { apikey: env.SUPABASE_PUBLISHABLE_KEY, Accept: 'application/json', 'Content-Type': 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetchImpl(url, {
      method: 'POST', headers, body: JSON.stringify(body ?? {}), redirect: 'error', signal: AbortSignal.timeout(8000),
    });
    let result = null;
    try { result = await response.json(); } catch { result = null; }
    return { status: response.status, ok: response.ok, result };
  };

  const guard = (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      res.status(405).json({ error: '허용되지 않는 요청입니다.' });
      return false;
    }
    if (!env.SUPABASE_URL || !env.SUPABASE_PUBLISHABLE_KEY) {
      res.status(500).json({ error: '서버 설정이 아직 끝나지 않았습니다.' });
      return false;
    }
    return true;
  };

  const unavailable = (res, status) => {
    console.error('auth: 로그인 서비스가 오류 상태를 돌려주거나 연결되지 않음', status ?? 'no-response');
    return res.status(502).json({ error: '로그인 서비스에 연결하지 못했습니다.' });
  };

  // 400·401·422는 자격 증명 문제로 보고 같은 문구로 거부합니다. 계정이 있는지 알려 주지 않기 위해서입니다.
  const sessionFrom = async (res, request, rejected) => {
    try {
      const result = await request();
      if (result.ok) {
        const session = toSession(result.result);
        return session ? res.status(200).json(session) : unavailable(res, result.status);
      }
      if ([400, 401, 403, 422].includes(result.status)) return res.status(401).json({ error: rejected });
      return unavailable(res, result.status);
    } catch {
      return unavailable(res);
    }
  };

  // POST /api/auth/login {email,password}
  const login = async (req, res) => {
    if (!guard(req, res)) return undefined;
    const body = readJsonBody(req);
    if (!body || !text(body.email, EMAIL_MAX) || !text(body.password, PASSWORD_MAX)) {
      return res.status(400).json({ error: '이메일과 비밀번호를 문자열로 보내 주세요.' });
    }
    return sessionFrom(res, () => upstream('token', {
      query: 'grant_type=password', body: { email: body.email.trim(), password: body.password },
    }), '이메일 또는 비밀번호가 맞지 않습니다.');
  };

  // POST /api/auth/refresh {refresh_token}
  const refresh = async (req, res) => {
    if (!guard(req, res)) return undefined;
    const body = readJsonBody(req);
    if (!body || typeof body.refresh_token !== 'string' || !REFRESH_TOKEN.test(body.refresh_token)) {
      return res.status(400).json({ error: '갱신 토큰을 문자열로 보내 주세요.' });
    }
    return sessionFrom(res, () => upstream('token', {
      query: 'grant_type=refresh_token', body: { refresh_token: body.refresh_token },
    }), '로그인이 만료되었습니다. 다시 로그인해 주세요.');
  };

  // POST /api/auth/logout (Authorization: Bearer 토큰). 토큰이 이미 무효여도 화면은 로그아웃된 것으로 다룹니다.
  const logout = async (req, res) => {
    if (!guard(req, res)) return undefined;
    const match = /^Bearer (\S+)$/u.exec(req.headers?.authorization ?? '');
    if (!match || !TOKEN.test(match[1])) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      return res.status(401).json({ error: '로그인이 필요합니다.' });
    }
    try {
      await upstream('logout', { token: match[1] });
    } catch {
      return unavailable(res);
    }
    return res.status(200).json({ ok: true });
  };

  return { login, refresh, logout };
}

export const authApi = createAuthApi();
