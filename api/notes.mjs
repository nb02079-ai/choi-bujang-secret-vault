// 서버에서만 실행됩니다. SUPABASE_URL과 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽습니다.
// 키 값은 응답·로그·오류 메시지에 절대 넣지 않습니다.
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: '허용되지 않는 요청입니다.' });
  }

  const baseUrl = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!baseUrl || !secretKey) {
    return res.status(500).json({ error: '서버 설정이 아직 끝나지 않았습니다.' });
  }

  try {
    const url = new URL('/rest/v1/vault_notes', baseUrl);
    url.searchParams.set('select', 'title,content');
    url.searchParams.set('order', 'created_at.asc,title.asc');
    const upstream = await fetch(url, {
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
}
