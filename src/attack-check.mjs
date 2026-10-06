// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
// These are the student's own requests, not a judge's decision.
const KEY_SHAPE = /\bsb_secret_[A-Za-z0-9_-]{6,}|\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----/u;

function publicApp(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  return app;
}

const send = (url, init = {}) => fetch(url, {
  ...init, redirect: 'error', signal: AbortSignal.timeout(10000),
});

async function readJson(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export async function runAttackChecks(config) {
  if (config.step !== 1 && config.step !== 2) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }
  const app = publicApp(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  if (config.step === 1) return firstStepChecks(config, app);
  return secondStepChecks(config, app);
}

async function firstStepChecks(config, app) {
  const response = await send(new URL('/data.json', app));
  let visible = false;
  if (response.ok) {
    const data = await readJson(response);
    visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
      && data.notes.length > 0;
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}

async function secondStepChecks(config, app) {
  const results = [];

  try {
    const response = await send(new URL('/data.json', app));
    const data = response.ok ? await readJson(response) : null;
    const count = Array.isArray(data?.notes) ? data.notes.length : null;
    const markerShown = data !== null && typeof data === 'object' && 'sampleMarker' in data;
    results.push({ attackId: 'static_data_json_empty',
      expected: '공개 /data.json에는 가상 메모와 시작 틀 확인 표시가 없어야 함',
      observed: markerShown ? `비로그인 /data.json에 시작 틀 확인 표시가 남아 있음 (HTTP ${response.status})`
        : count === 0 ? `비로그인 /data.json의 notes가 비어 있고 확인 표시가 없음 (HTTP ${response.status})`
          : count === null ? `/data.json을 읽었지만 notes 형식을 확인하지 못함 (HTTP ${response.status})`
            : `비로그인 /data.json에서 메모 ${count}건이 보임 (HTTP ${response.status})` });
  } catch {
    results.push({ attackId: 'static_data_json_empty',
      expected: '공개 /data.json에는 가상 메모와 시작 틀 확인 표시가 없어야 함', observed: '요청이 실패해 확인하지 못함' });
  }

  try {
    const response = await send(new URL('/api/notes', app));
    const text = await response.text();
    let data = null;
    try { data = JSON.parse(text); } catch { /* not JSON */ }
    const count = Array.isArray(data?.notes) ? data.notes.length : 0;
    results.push({ attackId: 'anonymous_api_read',
      expected: '비로그인 요청으로 /api/notes의 메모를 읽을 수 없어야 함 (2단계에서는 아직 막지 않은 약점)',
      observed: count > 0 ? `비로그인 요청에서 메모 ${count}건이 읽힘 (HTTP ${response.status})`
        : `비로그인 요청에서 메모가 읽히지 않음 (HTTP ${response.status})` });
    results.push({ attackId: 'api_response_no_key',
      expected: '/api/notes 응답에 비밀키 형태의 문자열이 없어야 함',
      observed: KEY_SHAPE.test(text) ? '응답에 비밀키 형태의 문자열이 있음' : '응답에 비밀키 형태의 문자열이 없음' });
  } catch {
    results.push({ attackId: 'anonymous_api_read',
      expected: '비로그인 요청으로 /api/notes의 메모를 읽을 수 없어야 함 (2단계에서는 아직 막지 않은 약점)',
      observed: '요청이 실패해 확인하지 못함' });
    results.push({ attackId: 'api_response_no_key',
      expected: '/api/notes 응답에 비밀키 형태의 문자열이 없어야 함', observed: '요청이 실패해 확인하지 못함' });
  }

  try {
    const response = await send(new URL('/api/notes', app), { method: 'POST' });
    await response.arrayBuffer();
    results.push({ attackId: 'api_post_rejected',
      expected: '/api/notes에 GET이 아닌 요청을 보내면 거부(405)되어야 함',
      observed: response.status === 405 ? '거부됨 (HTTP 405)' : `405가 아닌 응답이 옴 (HTTP ${response.status})` });
  } catch {
    results.push({ attackId: 'api_post_rejected',
      expected: '/api/notes에 GET이 아닌 요청을 보내면 거부(405)되어야 함', observed: '요청이 실패해 확인하지 못함' });
  }
  return results;
}
