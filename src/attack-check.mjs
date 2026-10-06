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
  if (![1, 2, 3].includes(config.step)) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }
  const app = publicApp(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  if (config.step === 1) return firstStepChecks(config, app);
  if (config.step === 2) return secondStepChecks(config, app);
  return thirdStepChecks(app);
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

async function staticDataCheck(app) {
  const expected = '공개 /data.json에는 가상 메모와 시작 틀 확인 표시가 없어야 함';
  try {
    const response = await send(new URL('/data.json', app));
    const data = response.ok ? await readJson(response) : null;
    const count = Array.isArray(data?.notes) ? data.notes.length : null;
    const markerShown = data !== null && typeof data === 'object' && 'sampleMarker' in data;
    return { attackId: 'static_data_json_empty', expected,
      observed: markerShown ? `비로그인 /data.json에 시작 틀 확인 표시가 남아 있음 (HTTP ${response.status})`
        : count === 0 ? `비로그인 /data.json의 notes가 비어 있고 확인 표시가 없음 (HTTP ${response.status})`
          : count === null ? `/data.json을 읽었지만 notes 형식을 확인하지 못함 (HTTP ${response.status})`
            : `비로그인 /data.json에서 메모 ${count}건이 보임 (HTTP ${response.status})` };
  } catch {
    return { attackId: 'static_data_json_empty', expected, observed: '요청이 실패해 확인하지 못함' };
  }
}

async function secondStepChecks(config, app) {
  const results = [];

  results.push(await staticDataCheck(app));

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

// 3단계: 로그인 토큰 없이 보낸 요청이 모두 거부되는지 확인합니다.
// 계정이 필요한 점검은 이 코드가 실행하지 않고 '미실행'으로 남깁니다. 계정 정보나 토큰을 코드에 넣지 않습니다.
const SAMPLE_ID = '00000000-0000-4000-8000-000000000000';
const JSON_HEADERS = { 'Content-Type': 'application/json' };

async function expectRejected(app, { attackId, expected, path, init = {}, status = 401, scanForKey = false }) {
  try {
    const response = await send(new URL(path, app), init);
    const text = await response.text();
    const keyShown = scanForKey && KEY_SHAPE.test(text);
    const observed = response.status === status ? `거부됨 (HTTP ${response.status})`
      : `${status}이 아닌 응답이 옴 (HTTP ${response.status})`;
    return { attackId, expected, observed: keyShown ? `${observed}. 응답에 비밀키 형태의 문자열이 있음` : observed };
  } catch {
    return { attackId, expected, observed: '요청이 실패해 확인하지 못함' };
  }
}

async function thirdStepChecks(app) {
  const forged = { ...JSON_HEADERS, 'x-user-id': 'admin', 'x-role': 'admin' };
  const note = JSON.stringify({ title: '점검', body: '점검', owner_id: SAMPLE_ID, userId: SAMPLE_ID, role: 'admin' });
  const results = [await staticDataCheck(app)];
  for (const check of [
    { attackId: 'anonymous_list_rejected', expected: '토큰 없이 GET /api/notes를 보내면 거부(401)되어야 함',
      path: '/api/notes', scanForKey: true },
    { attackId: 'anonymous_create_rejected', expected: '토큰 없이 POST /api/notes를 보내면 거부(401)되어야 함',
      path: '/api/notes', init: { method: 'POST', headers: JSON_HEADERS, body: note } },
    { attackId: 'anonymous_get_one_rejected', expected: '토큰 없이 GET /api/notes/:id를 보내면 거부(401)되어야 함',
      path: `/api/notes/${SAMPLE_ID}` },
    { attackId: 'anonymous_update_rejected', expected: '토큰 없이 PUT /api/notes/:id를 보내면 거부(401)되어야 함',
      path: `/api/notes/${SAMPLE_ID}`, init: { method: 'PUT', headers: JSON_HEADERS, body: note } },
    { attackId: 'anonymous_delete_rejected', expected: '토큰 없이 DELETE /api/notes/:id를 보내면 거부(401)되어야 함',
      path: `/api/notes/${SAMPLE_ID}`, init: { method: 'DELETE' } },
    { attackId: 'forged_token_rejected', expected: '검증되지 않는 가짜 토큰으로 GET /api/notes를 보내면 거부(401)되어야 함',
      path: '/api/notes', init: { headers: { Authorization: 'Bearer aaa.bbb.ccc' } } },
    { attackId: 'forged_identity_rejected', expected: '토큰 없이 userId·role·owner_id를 위조해 POST /api/notes를 보내면 거부(401)되어야 함',
      path: '/api/notes', init: { method: 'POST', headers: forged, body: note } },
    { attackId: 'unsupported_method_rejected', expected: '허용하지 않은 방식(PATCH)은 거부(405)되어야 함',
      path: '/api/notes', init: { method: 'PATCH' }, status: 405 },
  ]) results.push(await expectRejected(app, check));

  results.push({ attackId: 'logged_in_crud', expected: '정상 A 로그인 뒤에는 메모를 추가·수정·삭제할 수 있어야 함',
    observed: '미실행. 계정 정보를 코드에 넣지 않으므로 브라우저에서 학생이 직접 확인함' });
  results.push({ attackId: 'cross_user_access', expected: 'B가 A의 메모를 읽거나 고치거나 지울 수 없어야 함 (4단계 목표)',
    observed: '미실행. 3단계에는 소유자 검사가 없어 막히지 않는 것이 알려진 허점이며 4단계에서 기록하고 고침' });
  return results;
}
