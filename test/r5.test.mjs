import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('first attack check reads public data.json without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/data.json');
    assert.equal(options.redirect, 'error');
    assert.match(result.observed, /확인 표시가 보임/u);
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /보이지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 2 identity keeps the configured step', () => {
  assert.equal(deploymentIdentity(env, { ...config, step: 2 }).step, 2);
  assert.throws(() => deploymentIdentity(env, { ...config, step: 3 }));
});

test('step 2 attack check records only requests it sent', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  try {
    globalThis.fetch = async (url, init = {}) => {
      const path = new URL(String(url)).pathname;
      calls.push(`${init.method ?? 'GET'} ${path}`);
      if (path === '/data.json') return Response.json({ notes: [] });
      if (init.method === 'POST') return new Response('no', { status: 405 });
      return Response.json({ notes: [{ title: 'a', content: 'b' }] });
    };
    const results = await runAttackChecks({ ...config, step: 2 });
    assert.deepEqual(calls, ['GET /data.json', 'GET /api/notes', 'POST /api/notes']);
    const byId = Object.fromEntries(results.map(item => [item.attackId, item.observed]));
    assert.match(byId.static_data_json_empty, /비어 있고/u);
    assert.match(byId.anonymous_api_read, /1건이 읽힘/u);
    assert.match(byId.api_response_no_key, /없음/u);
    assert.match(byId.api_post_rejected, /405/u);
    for (const item of results) {
      assert.deepEqual(Object.keys(item).sort(), ['attackId', 'expected', 'observed']);
      assert.doesNotMatch(JSON.stringify(item), /"title"|"content"/u);
    }
    assert.match(byId.static_data_json_empty, /확인 표시가 없음/u);
    globalThis.fetch = async (url) => (new URL(String(url)).pathname === '/data.json'
      ? Response.json({ sampleMarker: 'SAMPLE_NOTE_1', notes: [] })
      : Response.json({ notes: [] }));
    const marked = await runAttackChecks({ ...config, step: 2 });
    assert.match(marked.find(item => item.attackId === 'static_data_json_empty').observed, /확인 표시가 남아 있음/u);
    globalThis.fetch = async () => { throw new Error('network'); };
    const failed = await runAttackChecks({ ...config, step: 2 });
    assert.equal(failed.length, 4);
    assert.ok(failed.every(item => /확인하지 못함/u.test(item.observed)));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

function fakeResponse() {
  const res = { headers: {}, statusCode: 0, body: undefined };
  res.setHeader = (key, value) => { res.headers[key.toLowerCase()] = value; };
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (body) => { res.body = body; return res; };
  return res;
}

test('api/notes refuses without a verified login and never reads the data store', async () => {
  const { createHandler } = await import('../api/notes.mjs');
  const secret = 'sb_secret_testvalue_never_returned';
  const env = { SUPABASE_URL: 'https://example-project.supabase.co', SUPABASE_SECRET_KEY: secret };
  let storeCalls = 0;
  const seen = [];
  const handler = createHandler({
    env,
    verify: async (authorization) => { seen.push(authorization); return authorization === 'Bearer good.token.value' ? { kind: 'student', userId: 'u' } : null; },
    fetchImpl: async (url, init) => {
      storeCalls += 1;
      assert.equal(init.headers.apikey, secret);
      return Response.json([{ title: 'T', content: 'C', owner_id: 'hidden' }]);
    },
  });

  for (const headers of [{}, { authorization: 'Bearer bad.token.value' },
    { authorization: 'Bearer bad.token.value', 'x-user-id': 'admin', 'x-role': 'admin' }]) {
    const res = fakeResponse();
    await handler({ method: 'GET', headers, query: { userId: 'admin', role: 'admin' } }, res);
    assert.equal(res.statusCode, 401);
    assert.deepEqual(res.body, { error: '로그인이 필요합니다.' });
  }
  assert.equal(storeCalls, 0);

  const ok = fakeResponse();
  await handler({ method: 'GET', headers: { authorization: 'Bearer good.token.value', 'x-user-id': 'admin' } }, ok);
  assert.equal(ok.statusCode, 200);
  assert.deepEqual(ok.body, { notes: [{ title: 'T', content: 'C' }] });
  assert.doesNotMatch(JSON.stringify(ok.body), new RegExp(secret, 'u'));
  assert.equal(seen.at(-1), 'Bearer good.token.value');

  const post = fakeResponse();
  await handler({ method: 'POST', headers: { authorization: 'Bearer good.token.value' } }, post);
  assert.equal(post.statusCode, 405);

  const broken = createHandler({ env, verify: async () => { throw new TypeError('invalid_student_identity_provider'); }, fetchImpl: async () => { throw new Error('no'); } });
  const failed = fakeResponse();
  await broken({ method: 'GET', headers: { authorization: 'Bearer good.token.value' } }, failed);
  assert.equal(failed.statusCode, 500);
  assert.doesNotMatch(JSON.stringify(failed.body), new RegExp(secret, 'u'));
});

test('aleph.config.json identityProvider is accepted by the starter login verifier', async () => {
  const { createLoginVerifier } = await import('../src/verify-login.mjs');
  const { readFileSync } = await import('node:fs');
  const real = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
  const verifier = createLoginVerifier({ config: real, supabaseClient: { auth: { getClaims: async () => ({ error: new Error('x') }) } } });
  assert.equal(await verifier(undefined), null);
  assert.equal(await verifier('Bearer aaa.bbb.ccc'), null);
  assert.equal(real.identityProvider.audience, 'authenticated');
  assert.equal(real.identityProvider.jwksUrl, `${real.identityProvider.issuer}/.well-known/jwks.json`);
  assert.doesNotMatch(JSON.stringify(real.identityProvider), /secret|service_role|eyJ/iu);
});
