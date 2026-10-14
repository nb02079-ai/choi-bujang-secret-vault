// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, credentials, real names, or note bodies.
// These are the student's own requests, not a judge's decision.
// 키 모양 탐지 패턴은 실행할 때 조립해 저장소 파일에 키 형태 글자가 남지 않게 합니다.
const DASHES = '-'.repeat(5);
const PEM_KIND = ['PRIV', 'ATE KEY'].join('');
const KEY_SHAPE = new RegExp([
  String.raw`\bsb_${['sec', 'ret'].join('')}_[A-Za-z0-9_-]{6,}`,
  String.raw`\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}`,
  String.raw`${DASHES}BEGIN [A-Z ]*${PEM_KIND}${DASHES}`,
].join('|'), 'u');

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
  if (![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].includes(config.step)) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }
  const app = publicApp(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  if (config.step === 1) return firstStepChecks(config, app);
  if (config.step === 2) return secondStepChecks(config, app);
  if (config.step === 3) return thirdStepChecks(app);
  if (config.step === 4) return fourthStepChecks(config, app);
  if (config.step === 5) return fifthStepChecks(config, app);
  if (config.step === 6) return sixthStepChecks(config, app);
  if (config.step === 7) return seventhStepChecks(config, app);
  if (config.step === 8) return eighthStepChecks(config, app);
  if (config.step === 9) return ninthStepChecks(config, app);
  if (config.step === 10) return tenthStepChecks(config, app);
  if (config.step === 11) return eleventhStepChecks(config, app);
  return twelfthStepChecks(config, app);
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
      expected: '/api/notes 응답에 비공개 값 형태의 문자열이 없어야 함',
      observed: KEY_SHAPE.test(text) ? '응답에 비공개 값 형태의 문자열이 있음' : '응답에 비공개 값 형태의 문자열이 없음' });
  } catch {
    results.push({ attackId: 'anonymous_api_read',
      expected: '비로그인 요청으로 /api/notes의 메모를 읽을 수 없어야 함 (2단계에서는 아직 막지 않은 약점)',
      observed: '요청이 실패해 확인하지 못함' });
    results.push({ attackId: 'api_response_no_key',
      expected: '/api/notes 응답에 비공개 값 형태의 문자열이 없어야 함', observed: '요청이 실패해 확인하지 못함' });
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

async function expectRejected(app, { attackId, expected, path, init = {}, status = 401, statuses = [status], scanForKey = false }) {
  try {
    const response = await send(new URL(path, app), init);
    const text = await response.text();
    const keyShown = scanForKey && KEY_SHAPE.test(text);
    const observed = statuses.includes(response.status) ? `거부됨 (HTTP ${response.status})`
      : `${statuses.join('/')}이 아닌 응답이 옴 (HTTP ${response.status})`;
    return { attackId, expected, observed: keyShown ? `${observed}. 응답에 비공개 값 형태의 문자열이 있음` : observed };
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

// 4단계: 3단계의 토큰 없는 점검에, 공개용 anon 키로 Supabase Data API에 직접 보내는 점검을 더합니다.
// 공개 키는 화면 코드에 원래 들어 있는 값이라, 외부 사람이 하듯 배포된 페이지에서 읽어 씁니다.
// 요청은 존재하지 않는 id 조건이나 필수 칸이 빠진 본문만 써서, 권한이 잘못 열려 있어도 자료가 바뀌지 않게 합니다.
// authenticated 역할의 직접 접근과 A/B 로그인이 필요한 점검은 이 코드가 실행하지 않고 '미실행'으로 남깁니다.
// 5단계부터 화면에 공개 접속값이 없으므로, 학생이 자기 터미널의 환경변수 SUPABASE_PUBLISHABLE_KEY에 넣어 둔 값을 먼저 씁니다.
// 값은 결과·로그에 싣지 않습니다. 환경변수가 없으면 4단계처럼 배포된 페이지에서 찾습니다.
// 접두사는 실행할 때 조립해 저장소 파일에 키 형태 글자가 남지 않게 합니다.
const PUBLIC_ACCESS_PREFIX = ['sb', ['publi', 'shable'].join(''), ''].join('_');
const PUBLIC_ACCESS_VALUE = `${PUBLIC_ACCESS_PREFIX}[A-Za-z0-9_-]{10,}`;
async function readPublicAccessValue(app) {
  const fromEnv = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (typeof fromEnv === 'string' && new RegExp(`^${PUBLIC_ACCESS_VALUE}$`, 'u').test(fromEnv)) return fromEnv;
  try {
    const page = await (await send(app)).text();
    return new RegExp(PUBLIC_ACCESS_VALUE, 'u').exec(page)?.[0] ?? null;
  } catch {
    return null;
  }
}

async function fourthStepChecks(config, app) {
  let dataApi = null;
  try { dataApi = new URL('/rest/v1/vault_notes', new URL(config.identityProvider.issuer).origin); } catch { /* 미실행으로 남김 */ }
  return anonDirectChecks(app, dataApi);
}

async function anonDirectChecks(app, dataApi) {
  const kept = (await thirdStepChecks(app))
    .filter(item => !['logged_in_crud', 'cross_user_access'].includes(item.attackId));

  const anonChecks = [
    { attackId: 'anon_direct_read_rejected', expected: '공개 접속값으로 Data API에 직접 목록을 읽으면 거부되어야 함',
      query: '?select=*', init: {} },
    { attackId: 'anon_direct_create_rejected', expected: '공개 접속값으로 Data API에 직접 추가하면 거부되어야 함',
      query: '', init: { method: 'POST', headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' }, body: '{}' } },
    { attackId: 'anon_direct_update_rejected', expected: '공개 접속값으로 Data API에 직접 수정하면 거부되어야 함',
      query: `?id=eq.${SAMPLE_ID}`, init: { method: 'PATCH', headers: JSON_HEADERS, body: JSON.stringify({ title: '점검' }) } },
    { attackId: 'anon_direct_delete_rejected', expected: '공개 접속값으로 Data API에 직접 삭제하면 거부되어야 함',
      query: `?id=eq.${SAMPLE_ID}`, init: { method: 'DELETE' } },
  ];
  const key = dataApi ? await readPublicAccessValue(app) : null;
  for (const check of anonChecks) {
    if (!dataApi || !key) {
      kept.push({ attackId: check.attackId, expected: check.expected,
        observed: '미실행. 직접 요청에 쓸 공개 접속값(터미널 환경변수 또는 배포된 페이지)이나 Data API 주소를 찾지 못함' });
      continue;
    }
    kept.push(await expectRejected(app, {
      attackId: check.attackId, expected: check.expected, path: `${dataApi.href}${check.query}`, statuses: [401, 403],
      init: { ...check.init, headers: { ...check.init.headers, apikey: key } },
    }));
  }

  kept.push({ attackId: 'logged_in_own_crud', expected: '정상 A·B 로그인 뒤에는 각자 자기 메모를 읽고 추가·수정·삭제할 수 있어야 함',
    observed: '미실행. 계정 정보를 코드에 넣지 않으므로 브라우저에서 학생이 직접 확인함' });
  kept.push({ attackId: 'cross_user_access', expected: 'B가 A의 메모를 읽거나 고치거나 지울 수 없고 소유자도 바꿀 수 없어야 함',
    observed: '미실행. A·B 로그인이 필요해 이 코드는 실행하지 않음. 서버의 소유자 비교는 로컬 시험(가짜 검사기·메모리 저장소)으로만 확인함' });
  return kept;
}

// 5단계: 자료 요청은 서버 함수 한곳으로 모읍니다. 쿼리 없는 원본 자료 주소(config.originalApiUrl)를 공개 anon 키로 직접 불러
// 거부되는지, 그리고 메모가 하나도 보이지 않는지 기록합니다. authenticated 토큰이 필요한 점검은 미실행으로 남깁니다.
async function fifthStepChecks(config, app) {
  let original = null;
  try {
    original = new URL(config.originalApiUrl);
    if (original.protocol !== 'https:' || original.search || original.hash || original.username || original.password) original = null;
  } catch { /* 미실행으로 남김 */ }
  const results = (await anonDirectChecks(app, original))
    .filter(item => item.attackId !== 'logged_in_own_crud');

  results.push(await pageKeyCheck(app));

  const expected = '공개 접속값으로 원본 자료 주소를 직접 불러도 메모가 보이지 않아야 함';
  const key = original ? await readPublicAccessValue(app) : null;
  if (!original || !key) {
    results.push({ attackId: 'original_url_no_notes', expected,
      observed: '미실행. 원본 자료 주소(originalApiUrl)나 공개 접속값을 찾지 못함' });
  } else {
    try {
      const response = await send(`${original.href}?select=id&limit=1`, { headers: { apikey: key } });
      const data = response.ok ? await readJson(response) : null;
      const count = Array.isArray(data) ? data.length : null;
      results.push({ attackId: 'original_url_no_notes', expected,
        observed: !response.ok ? `거부됨, 메모가 보이지 않음 (HTTP ${response.status})`
          : count === 0 ? `메모가 보이지 않음 (HTTP ${response.status})`
            : count === null ? `응답 형식을 확인하지 못함 (HTTP ${response.status})`
              : `원본 주소에서 메모가 보임 (HTTP ${response.status})` });
    } catch {
      results.push({ attackId: 'original_url_no_notes', expected, observed: '요청이 실패해 확인하지 못함' });
    }
  }
  results.push({ attackId: 'authenticated_direct_rejected',
    expected: '로그인 토큰을 실어 원본 자료 주소를 직접 불러도 거부되어야 함',
    observed: '미실행. 로그인 토큰을 코드에 넣지 않으므로 이 코드는 실행하지 않음' });
  results.push({ attackId: 'logged_in_own_crud', expected: '정상 A 로그인 뒤에는 서버 함수로 자기 메모를 읽고 추가·수정·삭제할 수 있어야 함',
    observed: '미실행. 계정 정보를 코드에 넣지 않으므로 브라우저에서 학생이 직접 확인함' });
  return results;
}

// 6단계: 5단계 점검을 그대로 두고, 판정기(src/decider.mjs)에 가상 요청 두 건을 직접 넣어 본 결과를 더합니다.
// 네트워크 요청이 아닌 로컬 연습이며 미등록 기기 공격은 심판이 맡습니다.
async function sixthStepChecks(config, app) {
  const results = await fifthStepChecks(config, app);
  const expected = '등록 기기의 가상 요청은 allow, 미등록 기기의 가상 요청은 deny·device_not_registered여야 함';
  try {
    const { decide } = await import('./decider.mjs');
    const base = { schema: 'aleph.decision.v1', service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id' };
    const registered = await decide({ ...base, requestId: 'local-registered', deviceRegistered: true });
    const unregistered = await decide({ ...base, requestId: 'local-unregistered', deviceRegistered: false });
    const ok = registered.decision === 'allow'
      && unregistered.decision === 'deny' && unregistered.reasonCode === 'device_not_registered';
    results.push({ attackId: 'device_registered_local', expected,
      observed: `로컬 가상 요청 연습: 등록 ${registered.decision}, 미등록 ${unregistered.decision}·${unregistered.reasonCode} (${ok ? '기대와 같음' : '기대와 다름'}). 심판 판정이 아님` });
  } catch {
    results.push({ attackId: 'device_registered_local', expected, observed: '판정기를 불러오지 못해 확인하지 못함' });
  }
  return results;
}

// 7단계: 6단계 점검을 그대로 두고, 판정기에 가상 접속 사건 세 건을 직접 넣어 본 결과를 더합니다.
// 로컬 연습이며 실제 자료 차단, 재로그인 확인, 새 요청 허용은 계약이 준비되기 전이라 실행하지 않습니다.
async function seventhStepChecks(config, app) {
  const results = await sixthStepChecks(config, app);
  const expected = '복합 이상 가상 사건은 step_up·step_up_required, 재확인이 붙은 같은 사건과 정상 사건은 allow여야 함';
  try {
    const { decide } = await import('./decider.mjs');
    const base = { schema: 'aleph.decision.v1', service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id',
      deviceRegistered: true, stepUp: { verified: false, authAgeSeconds: null }, recentEvents: [] };
    const normal = await decide({ ...base, requestId: 'local-normal',
      signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 } });
    const unusual = { ...base, signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 },
      recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }] };
    const asked = await decide({ ...unusual, requestId: 'local-unusual' });
    const confirmed = await decide({ ...unusual, requestId: 'local-confirmed', stepUp: { verified: true, authAgeSeconds: 60 } });
    const ok = normal.decision === 'allow' && asked.decision === 'step_up'
      && asked.reasonCode === 'step_up_required' && confirmed.decision === 'allow';
    results.push({ attackId: 'step_up_required_local', expected,
      observed: `로컬 가상 사건 연습: 정상 ${normal.decision}, 복합 이상 ${asked.decision}·${asked.reasonCode}, 재확인 뒤 ${confirmed.decision} (${ok ? '기대와 같음' : '기대와 다름'}). 심판 판정이 아님. 다시 로그인 전 실제 자료 차단과 새 요청 허용은 미실행(제공 엔진의 새 로그인 시각 검증 계약을 확인하지 못함)` });
  } catch {
    results.push({ attackId: 'step_up_required_local', expected, observed: '판정기를 불러오지 못해 확인하지 못함. 실제 자료 차단과 새 요청 허용은 미실행' });
  }
  return results;
}

// 8단계: 5단계 점검에, 판정기에 가상 요청을 직접 넣어 본 결과 하나(decider_local)를 더합니다.
// 직접 점검은 20개를 넘길 수 없어 기기·추가 확인·구역 연습을 한 항목으로 합칩니다.
// 로컬 연습이며 심판 판정이 아닙니다. 다른 사람 메모의 거부는 자료 API의 로컬 시험으로만 확인합니다.
async function eighthStepChecks(config, app) {
  const results = await fifthStepChecks(config, app);
  const expected = '기기·추가 확인·구역 규칙: 미등록 기기 deny, 복합 이상 step_up, 정상 자기 메모 allow, 메모 목록·공지 쓰기·강사 자료 deny여야 함';
  try {
    const { decide } = await import('./decider.mjs');
    const base = { schema: 'aleph.decision.v1', service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id',
      deviceRegistered: true, stepUp: { verified: false, authAgeSeconds: null }, recentEvents: [],
      signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 } };
    const ask = (requestId, patch = {}) => decide({ ...base, requestId, ...patch });
    const own = await ask('local-own');
    const unregistered = await ask('local-unregistered', { deviceRegistered: false });
    const unusual = { signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 },
      recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }] };
    const asked = await ask('local-unusual', unusual);
    const confirmed = await ask('local-confirmed', { ...unusual, stepUp: { verified: true, authAgeSeconds: 60 } });
    const list = await ask('local-list', { route: 'GET /notes', path: '/notes' });
    const notice = await ask('local-notice-write', { service: 'notices', method: 'PUT', route: 'PUT /notices/:id', path: '/notices/demo' });
    const instructor = await ask('local-instructor', { service: 'instructor', route: 'GET /instructor/:id', path: '/instructor/demo' });
    const ok = own.decision === 'allow'
      && unregistered.decision === 'deny' && unregistered.reasonCode === 'device_not_registered'
      && asked.decision === 'step_up' && confirmed.decision === 'allow'
      && [list, notice, instructor].every(item => item.decision === 'deny');
    results.push({ attackId: 'decider_local', expected,
      observed: `로컬 가상 요청 연습: 자기 메모 ${own.decision}, 미등록 ${unregistered.decision}·${unregistered.reasonCode}, 복합 이상 ${asked.decision}, 재확인 뒤 ${confirmed.decision}, 메모 목록 ${list.decision}, 공지 쓰기 ${notice.decision}, 강사 자료 ${instructor.decision} (${ok ? '기대와 같음' : '기대와 다름'}). 심판 판정이 아님. 다른 사람 메모의 거부는 자료 API 로컬 시험으로만 확인함. 다시 로그인 전 실제 자료 차단과 새 요청 허용은 미실행(제공 엔진의 새 로그인 시각 검증 계약을 확인하지 못함)` });
  } catch {
    results.push({ attackId: 'decider_local', expected, observed: '판정기를 불러오지 못해 확인하지 못함. 실제 자료 차단과 새 요청 허용은 미실행' });
  }
  return results;
}

// 9단계: 8단계 점검에, 탐지 함수(src/detect.mjs)에 가상 사건을 직접 넣어 본 결과 하나(detect_local)를 더합니다.
// 직접 점검은 20개 이내여야 하므로 정확히 20개입니다. 로컬 연습이며 심판 판정이나 실제 회수가 아닙니다.
// 제안은 반환값뿐이고 회수 API 호출이나 기기 권한 변경은 하지 않습니다. 실제 회수와 걸린 시간은 심판이 확인합니다.
async function ninthStepChecks(config, app) {
  const results = await eighthStepChecks(config, app);
  const expected = '복합 의심(10분 120건 초과, 평소와 다른 네트워크, 확인된 기기 한 개)은 propose_revocation·burst_read와 대상, 정상 사건과 정상 기기는 observe여야 함';
  try {
    const { detect } = await import('./detect.mjs');
    const start = Date.UTC(2026, 9, 1, 0, 0, 0);
    const reads = (count, device, network) => Array.from({ length: count }, (_, index) => ({
      at: new Date(start + index * 2000).toISOString(), method: 'GET', identity: { sub: 'local_subject' }, deviceId: device,
      signals: { source: 'judge_fixture', network, region: 'local', hour: 14 } }));
    const normalDevice = 'a'.repeat(16);
    const suspectDevice = 'b'.repeat(16);
    const normal = detect(reads(30, normalDevice, 'usual'));
    const burstOnly = detect(reads(150, suspectDevice, 'usual'));
    const mixed = detect([...reads(30, normalDevice, 'usual'), ...reads(150, suspectDevice, 'unusual')]);
    const suspicious = detect(reads(150, suspectDevice, 'unusual'));
    const ok = normal.action === 'observe' && burstOnly.action === 'observe'
      && suspicious.action === 'propose_revocation' && suspicious.reasonCode === 'burst_read' && suspicious.device === suspectDevice
      && mixed.action === 'propose_revocation' && mixed.device === suspectDevice;
    results.push({ attackId: 'detect_local', expected,
      observed: `로컬 가상 사건 연습: 정상 ${normal.action}, 다량 조회만 ${burstOnly.action}, 복합 의심 ${suspicious.action}·${suspicious.reasonCode ?? '-'}(대상 기기 ${suspicious.device ? '1개' : '없음'}), 정상 기기와 섞인 경우 ${mixed.action}(대상 기기 ${mixed.device === suspectDevice ? '의심 기기 1개' : '없음'}) (${ok ? '기대와 같음' : '기대와 다름'}). 심판 판정이 아님. 실제 회수와 경과 시간은 심판이 확인하므로 미실행` });
  } catch {
    results.push({ attackId: 'detect_local', expected, observed: '탐지 함수를 불러오지 못해 확인하지 못함. 실제 회수와 경과 시간은 미실행' });
  }
  return results;
}

// 10단계: 9단계 점검에, 메모 한 건 복원과 정책 비교를 메모리 저장소와 가상 요청으로 직접 해 본 결과 하나(restore_local)를 더합니다.
// 직접 점검은 20개 이내여야 하므로 9단계의 detect_local 결과를 decider_local 항목에 합쳐 정확히 20개로 맞춥니다.
// 네트워크 요청이 아닌 로컬 연습이며 심판 판정이 아닙니다. 실제 DB 복원과 B 계정 확인은 실행하지 않습니다.
async function tenthStepChecks(config, app) {
  const results = await ninthStepChecks(config, app);
  const detectIndex = results.findIndex(item => item.attackId === 'detect_local');
  const decider = results.find(item => item.attackId === 'decider_local');
  if (detectIndex >= 0 && decider) {
    // 제출 묶음은 expected·observed를 각각 300자 이하로 요구하므로 두 연습의 결과를 요약해서 합칩니다.
    const same = item => item.observed.includes('(기대와 같음)');
    const both = same(decider) && same(results[detectIndex]);
    decider.expected = '판정기(기기·추가 확인·구역)와 탐지(10분 120건 초과 복합 의심은 propose_revocation, 정상 사건은 observe)가 기대대로 나와야 함';
    decider.observed = `로컬 가상 요청 연습: 판정기 ${same(decider) ? '기대와 같음' : '기대와 다름'}, 탐지 ${same(results[detectIndex]) ? '기대와 같음' : '기대와 다름'} (${both ? '모두 기대와 같음' : '기대와 다른 항목 있음'}). 심판 판정이 아님. 다시 로그인 전 실제 자료 차단, 실제 회수와 경과 시간은 미실행`;
    results.splice(detectIndex, 1);
  }
  const expected = '시험 계정 B의 메모 한 건 복원은 사본과 ID·소유자·내용 해시가 같고 다른 메모와 감사 기록은 그대로, A의 요청과 틀린 해시는 거부, 사본과 같은 정책은 차이 없음';
  const quiet = console.warn;
  try {
    const { createNotesApi, contentSha256 } = await import('./notes-api.mjs');
    const { currentPolicy, diffPolicy } = await import('./policy-diff.mjs');
    const [userA, userB] = ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'];
    const [noteA, noteB] = ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'];
    const original = { title: '로컬 연습 제목', content: '로컬 연습 내용' };
    const hash = contentSha256(original.title, original.content);
    const tables = {
      vault_notes: [{ id: noteB, owner_id: userB, title: '침해된 제목', content: '침해된 내용' },
        { id: noteA, owner_id: userA, title: 'A 제목', content: 'A 내용' }],
      vault_notes_backup: [{ id: noteB, owner_id: userB, ...original, content_sha256: hash }],
      vault_restore_audit: [],
    };
    const fetchImpl = async (url, init) => {
      const rows = tables[url.pathname.split('/').pop()];
      const query = Object.fromEntries(url.searchParams);
      const eq = field => (query[field]?.startsWith('eq.') ? query[field].slice(3) : undefined);
      const body = init.body ? JSON.parse(init.body) : undefined;
      const hit = rows.filter(row => (eq('id') === undefined || row.id === eq('id')) && (eq('owner_id') === undefined || row.owner_id === eq('owner_id')));
      const pick = row => (query.select ? Object.fromEntries(query.select.split(',').map(key => [key, row[key]])) : row);
      if (init.method === 'PATCH') { hit.forEach(row => Object.assign(row, body)); return Response.json(hit.map(pick)); }
      if (init.method === 'POST') { rows.push({ ...body }); return Response.json([pick({ ...body })], { status: 201 }); }
      return Response.json(hit.map(pick));
    };
    const tokens = { 'Bearer a': { kind: 'student', userId: userA }, 'Bearer b': { kind: 'student', userId: userB } };
    const api = createNotesApi({ verify: async authorization => tokens[authorization] ?? null, fetchImpl,
      env: { SUPABASE_URL: 'https://local-practice.invalid', SUPABASE_SECRET_KEY: 'local-practice-only' } });
    const ask = async (token, contentHash) => {
      const res = { statusCode: 0, setHeader() {}, status(code) { this.statusCode = code; return this; }, json() { return this; } };
      await api.restore({ method: 'POST', url: `/api/notes/${noteB}/restore`, headers: { authorization: `Bearer ${token}` }, body: { contentSha256: contentHash } }, res);
      return res.statusCode;
    };
    console.warn = () => {};
    const byA = await ask('a', hash);
    const wrongHash = await ask('b', 'f'.repeat(64));
    const othersBefore = JSON.stringify(tables.vault_notes[1]);
    const restoredStatus = await ask('b', hash);
    const row = tables.vault_notes.find(item => item.id === noteB);
    const restoredOk = restoredStatus === 200 && row.owner_id === userB && contentSha256(row.title, row.content) === hash
      && JSON.stringify(tables.vault_notes[1]) === othersBefore && tables.vault_restore_audit.length === 1;
    const same = JSON.parse(JSON.stringify(currentPolicy()));
    const breached = JSON.parse(JSON.stringify(currentPolicy()));
    breached.zoneRoutes.notes.push('GET /notes');
    const policyOk = diffPolicy(currentPolicy(), same).length === 0 && diffPolicy(breached, same).length === 1;
    const ok = byA === 404 && wrongHash === 409 && restoredOk && policyOk;
    results.push({ attackId: 'restore_local', expected,
      observed: `로컬 복원 연습(메모리 저장소): A의 요청 ${byA}, 틀린 해시 ${wrongHash}, B의 복원 ${restoredStatus}(ID·소유자·내용 해시 ${restoredOk ? '사본과 같음' : '사본과 다름'}, 감사 ${tables.vault_restore_audit.length}줄), 정책 비교 ${policyOk ? '정상' : '기대와 다름'} (${ok ? '기대와 같음' : '기대와 다름'}). 심판 판정이 아님. 실제 DB 복원과 B 계정 확인은 미실행` });
  } catch {
    results.push({ attackId: 'restore_local', expected, observed: '복원 연습을 불러오지 못해 확인하지 못함. 실제 DB 복원과 B 계정 확인은 미실행' });
  } finally {
    console.warn = quiet;
  }
  return results;
}

// 11단계: 10단계 점검에, 기기 승인 흐름을 메모리 저장소와 가상 요청으로 직접 해 본 결과를 더합니다.
// 직접 점검은 20개 이내이고 각 글은 300자 이하여야 하므로, 로컬 연습 결과(판정기·탐지, 메모 복원, 기기 승인)를
// local_practice 한 항목으로 합칩니다. 네트워크 요청이 아닌 로컬 연습이며 심판 판정이 아닙니다.
async function eleventhStepChecks(config, app) {
  const results = await tenthStepChecks(config, app);
  const quiet = console.warn;
  let deviceOk = false;
  try {
    const { createDeviceApi, createDeviceCheck, DEVICE_COOKIE } = await import('./device-api.mjs');
    const { createNotesApi } = await import('./notes-api.mjs');
    const [userA, noteA] = ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '11111111-1111-4111-8111-111111111111'];
    const tables = { vault_devices: [], vault_notes: [{ id: noteA, owner_id: userA, title: '로컬 연습 제목', content: '로컬 연습 내용' }] };
    const fetchImpl = async (url, init) => {
      const rows = tables[url.pathname.split('/').pop()];
      const query = Object.fromEntries(url.searchParams);
      const filters = Object.entries(query).filter(([key, value]) => !['select', 'limit', 'order'].includes(key) && value.startsWith('eq.'));
      const hit = rows.filter(row => filters.every(([key, value]) => String(row[key]) === value.slice(3)));
      const pick = row => (query.select ? Object.fromEntries(query.select.split(',').map(key => [key, row[key]])) : row);
      const body = init.body ? JSON.parse(init.body) : undefined;
      if (init.method === 'POST') { const row = { id: crypto.randomUUID(), ...body }; rows.push(row); return Response.json([pick(row)], { status: 201 }); }
      if (init.method === 'PATCH') { hit.forEach(row => Object.assign(row, body)); return Response.json(hit.map(pick)); }
      return Response.json(hit.map(pick));
    };
    const env = { SUPABASE_URL: 'https://local-practice.invalid', SUPABASE_SECRET_KEY: 'local-practice-only' };
    const verify = async authorization => (authorization === 'Bearer a' ? { kind: 'student', userId: userA } : null);
    const devices = createDeviceApi({ verify, env, fetchImpl });
    const notes = createNotesApi({ verify, env, fetchImpl, deviceCheck: createDeviceCheck({ env, fetchImpl }) });
    const ask = async (handler, method, { cookie, body } = {}) => {
      const res = { statusCode: 0, headers: {}, body: undefined, setHeader(key, value) { this.headers[key.toLowerCase()] = value; },
        status(code) { this.statusCode = code; return this; }, json(value) { this.body = value; return this; } };
      const headers = { authorization: 'Bearer a', ...(cookie ? { cookie: `${DEVICE_COOKIE}=${cookie}` } : {}) };
      await handler({ method, url: '/api/x', headers, body }, res);
      return res;
    };
    console.warn = () => {};
    const requested = await ask(devices.request, 'POST');
    const cookie = /=([A-Za-z0-9_-]{43});/u.exec(requested.headers['set-cookie'] ?? '')?.[1];
    const beforeApproval = await ask(notes.collection, 'GET', { cookie });
    const selfApproval = await ask(devices.approve, 'POST', { cookie, body: { code: requested.body?.code } });
    tables.vault_devices[0].status = 'approved';
    const afterApproval = await ask(notes.collection, 'GET', { cookie });
    const noCookie = await ask(notes.collection, 'GET');
    deviceOk = requested.statusCode === 201 && Boolean(cookie) && beforeApproval.statusCode === 403 && selfApproval.statusCode === 403
      && afterApproval.statusCode === 200 && noCookie.statusCode === 403 && !JSON.stringify(tables.vault_devices).includes(cookie);
  } catch {
    deviceOk = false;
  } finally {
    console.warn = quiet;
  }
  const decider = results.find(item => item.attackId === 'decider_local');
  const restore = results.find(item => item.attackId === 'restore_local');
  const same = item => Boolean(item) && item.observed.includes('기대와 같음') && !item.observed.includes('기대와 다름') && !item.observed.includes('기대와 다른');
  if (decider && restore) {
    const label = ok => (ok ? '기대와 같음' : '기대와 다름');
    results.splice(results.indexOf(restore), 1);
    decider.attackId = 'local_practice';
    decider.expected = '판정기·탐지, 메모 복원, 기기 승인 연습이 기대대로 나와야 함 (승인 전 자료 요청 403, 자기 승인 403, 승인 뒤 200)';
    decider.observed = `로컬 연습(가짜 저장소·가상 요청): 판정기·탐지 ${label(same(decider))}, 메모 복원 ${label(same(restore))}, 기기 승인 ${label(deviceOk)}. 심판 판정이 아님. 실제 DB 복원, 기기 승인 흐름, B 계정 확인, 실제 회수는 미실행`;
  }
  return results;
}

// 12단계: 11단계 점검의 local_practice 항목에, 작전실 요약과 1~11단계 재확인 표를 가짜 저장소로 직접 돌려 본 결과를 더합니다.
// 직접 점검은 20개 이내이고 각 글은 300자 이하여야 하므로 새 항목을 만들지 않고 local_practice에 한 문장을 더합니다.
// 로컬 연습이며 심판 판정이 아닙니다. 41종 공격 방어 여부는 목록과 심판 판정이 없어 이 점검에서 다루지 않습니다.
async function twelfthStepChecks(config, app) {
  const results = await eleventhStepChecks(config, app);
  const quiet = console.warn;
  let opsOk = false;
  let recheckOk = false;
  try {
    console.warn = () => {};
    const { createOpsApi } = await import('./ops-api.mjs');
    const { createDeviceCheck, DEVICE_COOKIE } = await import('./device-api.mjs');
    const { createHash, randomBytes, randomUUID } = await import('node:crypto');
    const user = randomUUID();
    const cookie = randomBytes(32).toString('base64url');
    const tables = {
      vault_devices: [{ id: randomUUID(), owner_id: user, secret_sha256: createHash('sha256').update(cookie).digest('hex'), status: 'approved', request_code: 'AAAA2222', created_at: new Date().toISOString(), decided_at: null, expires_at: null }],
      vault_notes_backup: [], vault_restore_audit: [],
    };
    const fetchImpl = async (url) => {
      const rows = tables[url.pathname.split('/').pop()] ?? [];
      const query = Object.fromEntries(url.searchParams);
      const filters = Object.entries(query).filter(([key, value]) => !['select', 'limit', 'order'].includes(key) && value.startsWith('eq.'));
      const hit = rows.filter(row => filters.every(([key, value]) => String(row[key]) === value.slice(3)));
      const columns = query.select?.split(',');
      return Response.json(hit.map(row => (columns ? Object.fromEntries(columns.map(key => [key, row[key]])) : row)));
    };
    const env = { SUPABASE_URL: 'https://local-practice.invalid', SUPABASE_SECRET_KEY: 'local-practice-only' };
    const verify = async authorization => (authorization === 'Bearer a' ? { kind: 'student', userId: user } : null);
    const ops = createOpsApi({ verify, env, fetchImpl, deviceCheck: createDeviceCheck({ env, fetchImpl }) });
    const ask = async (withCookie) => {
      const res = { statusCode: 0, body: undefined, setHeader() {}, status(code) { this.statusCode = code; return this; }, json(value) { this.body = value; return this; } };
      await ops.summary({ method: 'GET', url: '/api/ops/summary', headers: { authorization: 'Bearer a', ...(withCookie ? { cookie: `${DEVICE_COOKIE}=${cookie}` } : {}) } }, res);
      return res;
    };
    const approved = await ask(true);
    const unapproved = await ask(false);
    opsOk = approved.statusCode === 200 && approved.body?.revocation?.total === 1 && approved.body?.revocation?.counts?.approved === 1
      && approved.body?.recovery?.restores?.total === 0 && unapproved.statusCode === 403
      && !JSON.stringify(approved.body).includes(cookie);
    const { runRecheck } = await import('./recheck.mjs');
    const recheck = await runRecheck();
    recheckOk = recheck.summary.mismatch === 0 && recheck.summary.measured >= 40;
  } catch {
    opsOk = false;
    recheckOk = false;
  } finally {
    console.warn = quiet;
  }
  const merged = results.find(item => item.attackId === 'local_practice');
  if (merged) {
    const label = ok => (ok ? '기대와 같음' : '기대와 다름');
    merged.expected = `${merged.expected}. 작전실 요약(승인 기기 200, 미승인 403)과 재확인 표(불일치 0건)`;
    merged.observed = merged.observed.replace('. 심판 판정이 아님', `, 작전실 요약 ${label(opsOk)}, 재확인 표 ${label(recheckOk)}. 심판 판정이 아님`);
  }
  return results;
}

// 첫 화면에 Supabase 공개 접속값이나 토큰 모양 문자열이 없어야 합니다. 값은 결과에 싣지 않습니다.
async function pageKeyCheck(app) {
  const expected = '첫 화면 코드에 Supabase 공개 접속값이나 토큰 모양 문자열이 없어야 함';
  try {
    const response = await send(app);
    const page = await response.text();
    const shown = new RegExp(`${PUBLIC_ACCESS_VALUE}|eyJ[A-Za-z0-9_-]{12,}\\.eyJ[A-Za-z0-9_-]{12,}\\.[A-Za-z0-9_-]{8,}`, 'u').test(page);
    return { attackId: 'page_no_public_key', expected,
      observed: !response.ok ? `첫 화면을 읽지 못함 (HTTP ${response.status})`
        : shown ? `첫 화면 코드에 접속값 형태의 문자열이 보임 (HTTP ${response.status})`
          : `첫 화면 코드에 접속값 형태의 문자열이 없음 (HTTP ${response.status})` };
  } catch {
    return { attackId: 'page_no_public_key', expected, observed: '요청이 실패해 확인하지 못함' };
  }
}
