// 서버에서만 실행됩니다. SUPABASE_URL과 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽습니다.
// 키 값은 응답·로그·오류 메시지에 절대 넣지 않습니다.
// 요청의 로그인 토큰은 틀이 준 src/verify-login.mjs로만 검사합니다.
// 브라우저가 보낸 userId·role 같은 값은 읽지도 믿지도 않습니다.
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

let verifier;
const defaultVerify = (authorization) => {
  verifier ??= createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
  return verifier(authorization);
};

export function createHandler({ verify = defaultVerify, env = process.env, fetchImpl = fetch } = {}) {
  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      return res.status(405).json({ error: '허용되지 않는 요청입니다.' });
    }

    const baseUrl = env.SUPABASE_URL;
    const secretKey = env.SUPABASE_SECRET_KEY;
    if (!baseUrl || !secretKey) {
      return res.status(500).json({ error: '서버 설정이 아직 끝나지 않았습니다.' });
    }

    let identity;
    try {
      identity = await verify(req.headers.authorization);
    } catch (error) {
      // 검사기를 만들 때의 설정 오류만 여기로 옵니다. 메시지는 고정된 오류 이름입니다.
      console.error('notes: 로그인 검사기를 쓸 수 없음', error instanceof TypeError ? error.message : '알 수 없는 오류');
      return res.status(500).json({ error: '서버 설정이 아직 끝나지 않았습니다.' });
    }
    if (!identity) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      return res.status(401).json({ error: '로그인이 필요합니다.' });
    }

    try {
      const url = new URL('/rest/v1/vault_notes', baseUrl);
      url.searchParams.set('select', 'title,content');
      url.searchParams.set('order', 'created_at.asc,title.asc');
      const upstream = await fetchImpl(url, {
        headers: { apikey: secretKey, Accept: 'application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(8000),
      });
      if (!upstream.ok) {
        console.error('notes: 자료 저장소가 오류 상태를 돌려줌', upstream.status);
        return res.status(502).json({ error: '자료를 불러오지 못했습니다.' });
      }
      const rows = await upstream.json();
      const notes = Array.isArray(rows)
        ? rows.map(({ title, content }) => ({ title, content }))
        : [];
      return res.status(200).json({ notes });
    } catch {
      console.error('notes: 자료 저장소에 연결하지 못함');
      return res.status(502).json({ error: '자료를 불러오지 못했습니다.' });
    }
  };
}

export default createHandler();
