import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { setDeviceStatus, viewState } from '../public/app-shell.js';
import { buildOpsView } from '../public/ops-room.js';

// 11단계 과정 3/3: 기기 승인 전에는 보호 자료가 없고, 서버가 승인됨이라고 알린 뒤에만 기존 화면이 열린다.
const root = fileURLToPath(new URL('..', import.meta.url));
const html = readFileSync(`${root}public/index.html`, 'utf8');

test('화면 규칙: 보호 자료는 로그인했고 서버가 승인됨이라고 알린 경우에만 열린다', () => {
  const signedOut = viewState({ signedIn: false, status: 'approved' });
  assert.deepEqual([signedOut.showEditor, signedOut.showNotes, signedOut.showActions, signedOut.showRequest, signedOut.showApprove], [false, false, false, false, false]);
  assert.match(signedOut.message, /로그인하면/u);
  for (const status of ['unverified', 'pending', 'denied']) {
    const view = viewState({ signedIn: true, status });
    assert.equal(view.showEditor, false, status);
    assert.equal(view.showNotes, false, status);
    assert.equal(view.showApprove, false, status);
    assert.equal(view.showActions, true, status);
    assert.equal(view.showRequest, status === 'unverified', status);
    assert.match(view.message, /자료를 볼 수 없습니다/u, status);
  }
  const approved = viewState({ signedIn: true, status: 'approved' });
  assert.deepEqual([approved.showEditor, approved.showNotes, approved.showRequest, approved.showApprove], [true, true, false, true]);
  assert.equal(approved.message, '');
  // 알 수 없는 값, 설치 관련 값, 대소문자 다른 값은 승인으로 치지 않는다
  for (const status of [undefined, null, '', 'APPROVED', 'installed', 'standalone', 'true', 1, {}, '__proto__', 'toString']) {
    const view = viewState({ signedIn: true, status });
    assert.equal(view.showNotes, false, String(status));
    assert.equal(view.status, 'unverified', String(status));
  }
});

// 화면 스크립트를 가짜 문서와 가짜 서버로 실제로 실행합니다. sessionStorage 같은 저장소 객체는 일부러 주지 않아서
// 스크립트가 저장소를 쓰면 ReferenceError로 실패합니다.
const AsyncFunction = Object.getPrototypeOf(async function noop() {}).constructor;
function pageScript() {
  const text = html.replaceAll('\r\n', '\n');
  const start = text.indexOf('<script type="module">\n') + '<script type="module">\n'.length;
  const code = text.slice(start, text.indexOf('</script>', start));
  return code
    .replace(/^\s*import \{ setDeviceStatus, viewState \} from '\/app-shell\.js';\s*$/mu, 'const { setDeviceStatus, viewState } = shell;')
    .replace(/^\s*import \{ buildOpsView \} from '\/ops-room\.js';\s*$/mu, 'const { buildOpsView } = opsRoom;');
}
function openPage(serve) {
  const nodes = new Map();
  const make = () => ({
    hidden: false, textContent: '', value: '', disabled: false, dataset: {}, children: [], className: '', listeners: {},
    classList: { toggle() {}, add() {}, remove() {} }, maxLength: 0, required: false, type: '', rows: 0,
    addEventListener(type, handler) { this.listeners[type] = handler; },
    append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; },
    setAttribute() {}, focus() {}, reset() {},
  });
  const document = {
    querySelector(selector) { if (!nodes.has(selector)) nodes.set(selector, make()); return nodes.get(selector); },
    createElement() { return make(); },
  };
  const calls = [];
  const fetch = async (path, init = {}) => {
    calls.push({ path, method: init.method ?? 'GET', headers: init.headers ?? {}, credentials: init.credentials });
    const reply = await serve(path, init.method ?? 'GET');
    return { ok: reply.status >= 200 && reply.status < 300, status: reply.status, json: async () => reply.body };
  };
  const form = document.querySelector('#login-form');
  form.email = { value: 'a@example.test' };
  form.password = { value: 'not-a-real-password' };
  const run = new AsyncFunction('document', 'window', 'fetch', 'shell', 'opsRoom', pageScript());
  const ready = run(document, { confirm: () => true }, fetch, { setDeviceStatus, viewState }, { buildOpsView });
  const settle = async () => { for (let index = 0; index < 12; index += 1) await new Promise((resolve) => setImmediate(resolve)); };
  const q = (selector) => document.querySelector(selector);
  const noteCalls = () => calls.filter((call) => call.path.startsWith('/api/notes'));
  const login = async () => { await q('#login-form').listeners.submit({ preventDefault() {} }); await settle(); };
  return { ready, calls, q, settle, login, noteCalls };
}
const session = () => ({ status: 200, body: { access_token: 'access.test.value', refresh_token: 'refresh_test_value', expires_at: Math.floor(Date.now() / 1000) + 3600, email: 'a@example.test' } });
const NOTES = [{ id: '11111111-1111-4111-8111-111111111111', title: '내 메모', body: '내 내용' }];

test('화면 실행: 승인 전에는 자료 요청을 보내지 않고 자료가 없으며, 승인된 뒤에만 기존 화면이 열린다', async () => {
  let deviceReply = { status: 200, body: { status: 'unverified' } };
  const page = openPage(async (path, method) => {
    if (path === '/api/auth/login') return session();
    if (path === '/api/device/status') return deviceReply;
    if (path === '/api/device/request') return { status: 201, body: { status: 'pending', code: 'ABCD2345', expiresInSeconds: 900 } };
    if (path === '/api/notes' && method === 'GET') return { status: 200, body: NOTES };
    return { status: 404, body: {} };
  });
  await page.ready;
  await page.settle();
  // 로그인 전: 보호 영역 없음, 상태는 확인 전
  assert.equal(page.q('#editor').hidden, true);
  assert.equal(page.q('#device-status').textContent, '확인 전');
  assert.match(page.q('#notes').children[0].textContent, /로그인하면/u);
  // 로그인했지만 기기가 확인 전: 상태만 묻고 자료는 묻지 않는다
  await page.login();
  assert.deepEqual(page.calls.map((call) => call.path), ['/api/auth/login', '/api/device/status']);
  assert.equal(page.noteCalls().length, 0);
  assert.equal(page.q('#editor').hidden, true);
  assert.equal(page.q('#device-request').hidden, false);
  assert.equal(page.q('#device-approve-form').hidden, true);
  assert.match(page.q('#notes').children[0].textContent, /승인되기 전에는 자료를 볼 수 없습니다/u);
  assert.equal(page.q('#device-status').textContent, '확인 전');
  // 승인 요청: 요청만 보내고 자료는 여전히 없다
  await page.q('#device-request').listeners.click();
  await page.settle();
  assert.equal(page.calls.at(-1).path, '/api/device/request');
  assert.equal(page.q('#device-status').textContent, '승인 대기');
  assert.match(page.q('#device-code').textContent, /ABCD2345/u);
  assert.equal(page.q('#device-code').hidden, false);
  assert.equal(page.noteCalls().length, 0);
  assert.equal(page.q('#editor').hidden, true);
  // 서버가 아직 대기라고 하면 새로고침해도 자료는 없다
  deviceReply = { status: 200, body: { status: 'pending', code: 'ABCD2345', expiresInSeconds: 800 } };
  await page.q('#device-refresh').listeners.click();
  await page.settle();
  assert.equal(page.noteCalls().length, 0);
  // 서버가 승인됨이라고 알려 주면 그때 기존 화면이 열린다
  deviceReply = { status: 200, body: { status: 'approved' } };
  await page.q('#device-refresh').listeners.click();
  await page.settle();
  assert.equal(page.q('#device-status').textContent, '승인됨');
  assert.equal(page.q('#editor').hidden, false);
  assert.equal(page.q('#device-approve-form').hidden, false);
  assert.equal(page.noteCalls().length, 1);
  assert.deepEqual({ path: page.noteCalls()[0].path, method: page.noteCalls()[0].method }, { path: '/api/notes', method: 'GET' });
  assert.equal(page.q('#notes').children.length, 1);
  // 서버에 보내는 요청은 로그인 토큰 헤더와 쿠키 전송 설정만 쓴다. 기기 값을 직접 실어 보내지 않는다.
  for (const call of page.calls.filter((item) => item.path.startsWith('/api/device') || item.path.startsWith('/api/notes'))) {
    assert.equal(call.credentials, 'same-origin', call.path);
    assert.deepEqual(Object.keys(call.headers).filter((name) => !['Authorization', 'Content-Type'].includes(name)), [], call.path);
  }
});

test('화면 실행: 상태를 확인하지 못하거나 서버가 승인하지 않으면 자료를 열지 않는다', async () => {
  for (const reply of [{ status: 500, body: { error: '기기 상태를 확인하지 못했습니다.' } }, { status: 200, body: { status: 'denied' } },
    { status: 200, body: { status: 'installed' } }, { status: 200, body: {} }, { status: 502, body: null }]) {
    const page = openPage(async (path) => {
      if (path === '/api/auth/login') return session();
      if (path === '/api/device/status') return reply;
      return { status: 200, body: NOTES };
    });
    await page.ready;
    await page.login();
    assert.equal(page.noteCalls().length, 0, JSON.stringify(reply));
    assert.equal(page.q('#editor').hidden, true, JSON.stringify(reply));
    assert.notEqual(page.q('#device-status').textContent, '승인됨', JSON.stringify(reply));
  }
  // 승인 상태 요청이 연결 오류로 실패해도 닫힌다
  const broken = openPage(async (path) => {
    if (path === '/api/auth/login') return session();
    throw new Error('연결 실패');
  });
  await broken.ready;
  await broken.login();
  assert.equal(broken.noteCalls().length, 0);
  assert.equal(broken.q('#editor').hidden, true);
});

test('화면 실행: 서버가 나중에 기기 승인을 요구하면 화면도 확인 전으로 돌아가 자료를 숨긴다', async () => {
  let blocked = false;
  const page = openPage(async (path) => {
    if (path === '/api/auth/login') return session();
    if (path === '/api/device/status') return { status: 200, body: { status: 'approved' } };
    if (path === '/api/notes') return blocked ? { status: 403, body: { error: '기기 승인이 필요합니다.', code: 'device_not_approved' } } : { status: 200, body: NOTES };
    return { status: 404, body: {} };
  });
  await page.ready;
  await page.login();
  assert.equal(page.q('#editor').hidden, false);
  blocked = true;
  await page.q('#note-form').listeners.submit({ preventDefault() {} });
  await page.settle();
  assert.equal(page.q('#editor').hidden, true);
  assert.equal(page.q('#device-status').textContent, '확인 전');
  assert.match(page.q('#notes').children[0].textContent, /승인되기 전에는 자료를 볼 수 없습니다/u);
});

test('화면 실행: 승인된 기기에서 다른 기기의 코드를 승인하고, 로그아웃하면 자료와 승인 상태가 사라진다', async () => {
  const page = openPage(async (path, method) => {
    if (path === '/api/auth/login') return session();
    if (path === '/api/auth/logout') return { status: 200, body: {} };
    if (path === '/api/device/status') return { status: 200, body: { status: 'approved' } };
    if (path === '/api/device/approve') return { status: 200, body: { approved: true } };
    if (path === '/api/notes' && method === 'GET') return { status: 200, body: NOTES };
    return { status: 404, body: {} };
  });
  await page.ready;
  await page.login();
  page.q('#approve-code').value = 'abcd-2345';
  await page.q('#device-approve-form').listeners.submit({ preventDefault() {} });
  await page.settle();
  assert.ok(page.calls.find((call) => call.path === '/api/device/approve'));
  assert.match(page.q('#device-message').textContent, /승인했습니다/u);
  assert.equal(page.q('#approve-code').value, '');
  await page.q('#logout').listeners.click();
  await page.settle();
  assert.equal(page.q('#editor').hidden, true);
  assert.equal(page.q('#device-status').textContent, '확인 전');
  assert.equal(page.q('#device-actions').hidden, true);
  assert.match(page.q('#notes').children[0].textContent, /로그인하면/u);
});
