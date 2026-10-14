// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, credentials, real names, or note bodies.
// These are the student's own requests, not a judge's decision.
//
// 제출 묶음(npm run bundle)은 격리 환경에서 실행될 수 있습니다. 그래서 이 파일은 다음을 지킵니다.
// - 불러오는 모듈은 node:fs·node:path·node:url·node:child_process(git 읽기)·node:crypto(randomUUID·sha256)와
//   이 저장소의 decider.mjs·detect.mjs·policy-diff.mjs뿐입니다. npm 패키지와 node:net은 불러오지 않습니다.
//   (로그인 검사 모듈 verify-login.mjs를 거치는 notes-api, device-api, ops-api, recheck는 불러오지 않습니다.)
// - 네트워크 요청은 공개 HTTPS 주소로 보내는 GET·HEAD뿐입니다. 쓰기 요청(POST·PUT·PATCH·DELETE)이 필요한 점검은
//   보내지 않고 observed를 not_run으로 둡니다. 이유는 expected 끝에 적습니다.
// - 실행하지 않은 점검은 모두 observed가 정확히 not_run입니다. 통과로 바꾸지 않습니다.
// 메모 복원, 기기 승인, 작전실의 로컬 연습은 npm run recheck와 node --test에서 실행합니다.
//
// 키 모양 탐지 패턴은 실행할 때 조립해 저장소 파일에 키 형태 글자가 남지 않게 합니다.
const DASHES = '-'.repeat(5);
const PEM_KIND = ['PRIV', 'ATE KEY'].join('');
const KEY_SHAPE = new RegExp([
  String.raw`\bsb_${['sec', 'ret'].join('')}_[A-Za-z0-9_-]{6,}`,
  String.raw`\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}`,
  String.raw`${DASHES}BEGIN [A-Z ]*${PEM_KIND}${DASHES}`,
].join('|'), 'u');

const NOT_RUN = 'not_run';
const MAX_TEXT = 300;
const WRITE_REASON = '쓰기 요청이라 격리 환경에서는 보내지 않음';

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

// 요청은 GET·HEAD만 보냅니다. 다른 방식이 들어오면 보내지 않고 오류를 냅니다.
const send = (url, init = {}) => {
  const method = String(init.method ?? 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') throw new Error('write_request_not_allowed');
  return fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(10000) });
};

// 실행하지 않은 점검: observed는 정확히 not_run, 이유는 expected 끝에 적습니다.
const notRun = (attackId, expected, reason) => ({ attackId, expected: `${expected} (${reason})`.slice(0, MAX_TEXT), observed: NOT_RUN });

async function readJson(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

// 결과를 한 번 더 정리합니다. 옛 문장 "미실행. 이유"가 남아 있으면 not_run으로 바꾸고 글자 수 상한을 지킵니다.
function finalize(results) {
  return results.map((item) => {
    if (typeof item.observed === 'string' && item.observed.startsWith('미실행')) {
      const reason = item.observed.replace(/^미실행\.?\s*/u, '');
      return { attackId: item.attackId, expected: `${item.expected} (${reason})`.slice(0, MAX_TEXT), observed: NOT_RUN };
    }
    return { attackId: item.attackId, expected: String(item.expected).slice(0, MAX_TEXT), observed: String(item.observed).slice(0, MAX_TEXT) };
  });
}

export async function runAttackChecks(config) {
  if (![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].includes(config.step)) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }
  const app = publicApp(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  return finalize(await dispatch(config, app));
}

function dispatch(config, app) {
  if (config.step === 1) return firstStepChecks(config, app);
  if (config.step === 2) return secondStepChecks(config, app);
  if (config.step === 3) return thirdStepChecks(app);
  if (config.step === 4) return fourthStepChecks(config, app);
  if (config.step === 5) return fifthStepChecks(config, app);
  if (config.step === 6) return sixthStepChecks(config, app);
  if (config.step === 7) return seventhStepChecks(config, app);
  if (config.step === 8) return eighthStepChecks(config, app);
  if (config.step === 9) return ninthStepChecks(config, app);
  return practiceChecks(config, app);
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

  results.push(notRun('api_post_rejected', '/api/notes에 GET이 아닌 요청을 보내면 거부(405)되어야 함', WRITE_REASON));
  return results;
}

// 3단계: 로그인 토큰 없이 보낸 요청이 거부되는지 확인합니다. 읽기(GET) 점검만 실제로 보냅니다.
// 쓰기 요청이 필요한 점검과 계정이 필요한 점검은 not_run으로 남깁니다. 계정 정보나 토큰을 코드에 넣지 않습니다.
const SAMPLE_ID = '00000000-0000-4000-8000-000000000000';

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
  const results = [await staticDataCheck(app)];
  for (const check of [
    { attackId: 'anonymous_list_rejected', expected: '토큰 없이 GET /api/notes를 보내면 거부(401)되어야 함',
      path: '/api/notes', scanForKey: true },
    { attackId: 'anonymous_create_rejected', expected: '토큰 없이 POST /api/notes를 보내면 거부(401)되어야 함', write: true },
    { attackId: 'anonymous_get_one_rejected', expected: '토큰 없이 GET /api/notes/:id를 보내면 거부(401)되어야 함',
      path: `/api/notes/${SAMPLE_ID}` },
    { attackId: 'anonymous_update_rejected', expected: '토큰 없이 PUT /api/notes/:id를 보내면 거부(401)되어야 함', write: true },
    { attackId: 'anonymous_delete_rejected', expected: '토큰 없이 DELETE /api/notes/:id를 보내면 거부(401)되어야 함', write: true },
    { attackId: 'forged_token_rejected', expected: '검증되지 않는 가짜 토큰으로 GET /api/notes를 보내면 거부(401)되어야 함',
      path: '/api/notes', init: { headers: { Authorization: 'Bearer aaa.bbb.ccc' } } },
    { attackId: 'forged_identity_rejected', expected: '토큰 없이 userId·role·owner_id를 위조해 POST /api/notes를 보내면 거부(401)되어야 함', write: true },
    { attackId: 'unsupported_method_rejected', expected: '허용하지 않은 방식(PATCH)은 거부(405)되어야 함', write: true },
  ]) {
    results.push(check.write ? notRun(check.attackId, check.expected, WRITE_REASON) : await expectRejected(app, check));
  }

  results.push(notRun('logged_in_crud', '정상 A 로그인 뒤에는 메모를 추가·수정·삭제할 수 있어야 함', '계정 정보를 코드에 넣지 않으므로 브라우저에서 학생이 직접 확인함'));
  results.push(notRun('cross_user_access', 'B가 A의 메모를 읽거나 고치거나 지울 수 없어야 함 (4단계 목표)', '3단계에는 소유자 검사가 없어 4단계에서 고침'));
  return results;
}

// 4단계: 3단계의 토큰 없는 점검에, 공개용 anon 키로 Supabase Data API에 직접 읽기(GET)를 보내는 점검을 더합니다.
// 5단계부터 화면에 공개 접속값이 없으므로, 학생이 자기 터미널의 환경변수 SUPABASE_PUBLISHABLE_KEY에 넣어 둔 값을 먼저 씁니다.
// 값은 결과·로그에 싣지 않습니다. 환경변수가 없으면 4단계처럼 배포된 페이지에서 찾습니다.
// 직접 추가·수정·삭제는 쓰기 요청이라 보내지 않고 not_run으로 남깁니다.
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
  try { dataApi = new URL('/rest/v1/vault_notes', new URL(config.identityProvider.issuer).origin); } catch { /* not_run으로 남김 */ }
  return anonDirectChecks(app, dataApi);
}

async function anonDirectChecks(app, dataApi) {
  const kept = (await thirdStepChecks(app))
    .filter(item => !['logged_in_crud', 'cross_user_access'].includes(item.attackId));

  const key = dataApi ? await readPublicAccessValue(app) : null;
  if (!dataApi || !key) {
    kept.push(notRun('anon_direct_read_rejected', '공개 접속값으로 Data API에 직접 목록을 읽으면 거부되어야 함',
      '직접 요청에 쓸 공개 접속값(터미널 환경변수 또는 배포된 페이지)이나 Data API 주소를 찾지 못함'));
  } else {
    kept.push(await expectRejected(app, {
      attackId: 'anon_direct_read_rejected', expected: '공개 접속값으로 Data API에 직접 목록을 읽으면 거부되어야 함',
      path: `${dataApi.href}?select=*`, statuses: [401, 403], init: { headers: { apikey: key } },
    }));
  }
  kept.push(notRun('anon_direct_create_rejected', '공개 접속값으로 Data API에 직접 추가하면 거부되어야 함', WRITE_REASON));
  kept.push(notRun('anon_direct_update_rejected', '공개 접속값으로 Data API에 직접 수정하면 거부되어야 함', WRITE_REASON));
  kept.push(notRun('anon_direct_delete_rejected', '공개 접속값으로 Data API에 직접 삭제하면 거부되어야 함', WRITE_REASON));

  kept.push(notRun('logged_in_own_crud', '정상 A·B 로그인 뒤에는 각자 자기 메모를 읽고 추가·수정·삭제할 수 있어야 함', '계정 정보를 코드에 넣지 않으므로 브라우저에서 학생이 직접 확인함'));
  kept.push(notRun('cross_user_access', 'B가 A의 메모를 읽거나 고치거나 지울 수 없고 소유자도 바꿀 수 없어야 함',
    'A·B 로그인이 필요해 실행하지 않음. 서버의 소유자 비교는 node --test와 npm run recheck의 가짜 저장소로만 확인함'));
  return kept;
}

// 5단계: 자료 요청은 서버 함수 한곳으로 모읍니다. 쿼리 없는 원본 자료 주소(config.originalApiUrl)를 공개 anon 키로 직접 불러
// 거부되는지, 그리고 메모가 하나도 보이지 않는지 기록합니다. authenticated 토큰이 필요한 점검은 not_run으로 남깁니다.
async function fifthStepChecks(config, app) {
  let original = null;
  try {
    original = new URL(config.originalApiUrl);
    if (original.protocol !== 'https:' || original.search || original.hash || original.username || original.password) original = null;
  } catch { /* not_run으로 남김 */ }
  const results = (await anonDirectChecks(app, original))
    .filter(item => item.attackId !== 'logged_in_own_crud');

  results.push(await pageKeyCheck(app));

  const expected = '공개 접속값으로 원본 자료 주소를 직접 불러도 메모가 보이지 않아야 함';
  const key = original ? await readPublicAccessValue(app) : null;
  if (!original || !key) {
    results.push(notRun('original_url_no_notes', expected, '원본 자료 주소(originalApiUrl)나 공개 접속값을 찾지 못함'));
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
  results.push(notRun('authenticated_direct_rejected', '로그인 토큰을 실어 원본 자료 주소를 직접 불러도 거부되어야 함', '로그인 토큰을 코드에 넣지 않으므로 실행하지 않음'));
  results.push(notRun('logged_in_own_crud', '정상 A 로그인 뒤에는 서버 함수로 자기 메모를 읽고 추가·수정·삭제할 수 있어야 함', '계정 정보를 코드에 넣지 않으므로 브라우저에서 학생이 직접 확인함'));
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
      observed: `로컬 가상 요청 연습: 자기 메모 ${own.decision}, 미등록 ${unregistered.decision}·${unregistered.reasonCode}, 복합 이상 ${asked.decision}, 재확인 뒤 ${confirmed.decision}, 메모 목록 ${list.decision}, 공지 쓰기 ${notice.decision}, 강사 자료 ${instructor.decision} (${ok ? '기대와 같음' : '기대와 다름'}). 심판 판정이 아님. 다른 사람 메모의 거부는 자료 API 로컬 시험으로만 확인함` });
  } catch {
    results.push({ attackId: 'decider_local', expected, observed: '판정기를 불러오지 못해 확인하지 못함' });
  }
  return results;
}

// 9단계: 8단계 점검에, 탐지 함수(src/detect.mjs)에 가상 사건을 직접 넣어 본 결과 하나(detect_local)를 더합니다.
// 로컬 연습이며 심판 판정이나 실제 회수가 아닙니다. 제안은 반환값뿐이고 실제 회수와 걸린 시간은 심판이 확인합니다.
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

// 정책 사본 비교 연습: 같은 정책은 차이가 없고, 전체 목록 경로가 더해진 정책은 차이가 1건이어야 합니다.
// policy-diff.mjs는 node:fs·node:crypto와 decider.mjs만 불러옵니다.
async function policyComparisonOk() {
  try {
    const { currentPolicy, diffPolicy } = await import('./policy-diff.mjs');
    const base = currentPolicy();
    const same = JSON.parse(JSON.stringify(base));
    const breached = JSON.parse(JSON.stringify(base));
    breached.zoneRoutes.notes.push('GET /notes');
    return diffPolicy(base, same).length === 0 && diffPolicy(breached, same).length === 1;
  } catch {
    return false;
  }
}

// 10~12단계: 9단계 점검의 decider_local·detect_local을 local_practice 한 항목으로 합치고 정책 비교 연습을 더합니다.
// 직접 점검은 20개 이내이고 각 글은 300자 이하여야 합니다. 로컬 연습이며 심판 판정이 아닙니다.
// 메모 복원, 기기 승인, 작전실 연습은 로그인 검사 모듈(npm 패키지와 node:net)을 거치므로 제출 묶음에서는 실행하지 않고
// npm run recheck와 node --test에서 실행합니다.
async function practiceChecks(config, app) {
  const results = await ninthStepChecks(config, app);
  const decider = results.find(item => item.attackId === 'decider_local');
  const detect = results.find(item => item.attackId === 'detect_local');
  const same = item => Boolean(item) && item.observed.includes('(기대와 같음)') && !item.observed.includes('(기대와 다름)');
  const label = ok => (ok ? '기대와 같음' : '기대와 다름');
  const policyOk = await policyComparisonOk();
  const merged = results.filter(item => !['decider_local', 'detect_local'].includes(item.attackId));
  merged.push({
    attackId: 'local_practice',
    expected: '판정기·탐지와 정책 비교 연습이 기대대로 나와야 함 (미등록 기기 deny, 복합 이상 step_up, 메모 목록·공지 쓰기 deny, 복합 의심 propose_revocation, 정책 차이 계산)',
    observed: `로컬 연습(가상 요청): 판정기 ${label(same(decider))}, 탐지 ${label(same(detect))}, 정책 비교 ${label(policyOk)}. 심판 판정이 아님. 메모 복원·기기 승인·작전실 연습은 격리 환경에서 불러올 수 없어 제외했고 npm run recheck와 시험에서 실행함. 실제 회수와 경과 시간은 미실행`,
  });
  return merged;
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
