import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  DEVICE_NOTE, OFFLINE_NOTE, deviceStatusLabel, installStateText, normalizeDeviceStatus, setDeviceStatus, startShell,
} from '../public/app-shell.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const read = (path) => readFileSync(`${root}${path}`, 'utf8');
const html = read('public/index.html');
const shell = read('public/app-shell.js');
const worker = read('public/sw.js');
const manifest = JSON.parse(read('public/manifest.webmanifest'));
// 주석은 빼고 코드만 검사합니다.
const codeOnly = (text) => text.replace(/\/\*[\s\S]*?\*\//gu, '').replace(/^\s*\/\/.*$/gmu, '');
const DISCLAIMER ='앱을 설치했다는 표시만으로 이 기기가 확인된 것은 아닙니다';

// 브라우저 없이 화면 보조 코드를 시험하기 위한 가짜 문서·창입니다.
function fakeBrowser({ standalone = false, online = true } = {}) {
  const nodes = {};
  for (const id of ['#device-status', '#device-note', '#install-state', '#offline-banner']) {
    nodes[id] = { textContent: '', dataset: {}, hidden: id === '#offline-banner' };
  }
  nodes['#device-status'].textContent = '확인 전';
  nodes['#device-status'].dataset.status = 'unverified';
  const listeners = {};
  const registered = [];
  return {
    nodes, listeners, registered,
    document: { querySelector: (selector) => nodes[selector] ?? null },
    window: { matchMedia: (query) => ({ matches: standalone && query.includes('standalone') }), addEventListener: (type, handler) => { listeners[type] = handler; } },
    navigator: { onLine: online, standalone: false, serviceWorker: { register: (...args) => { registered.push(args); return Promise.resolve(); } } },
  };
}

test('manifest: 앱 이름, 시작 주소, 설치 화면 모드, 색, 아이콘이 있고 기기 확인을 단정하지 않는다', () => {
  assert.equal(manifest.name, 'BYTE BACK 내 자료실');
  assert.equal(manifest.short_name, '내 자료실');
  assert.equal(manifest.start_url, '/');
  assert.equal(manifest.scope, '/');
  assert.equal(manifest.display, 'standalone');
  assert.equal(manifest.lang, 'ko');
  assert.match(manifest.background_color, /^#[0-9a-f]{6}$/u);
  assert.match(manifest.theme_color, /^#[0-9a-f]{6}$/u);
  assert.match(manifest.description, /서버와 판정기가 정합니다/u);
  assert.doesNotMatch(JSON.stringify(manifest), /확인 완료|승인 완료|승인됨/u);
  const sizes = manifest.icons.map((icon) => icon.sizes);
  assert.ok(sizes.includes('192x192') && sizes.includes('512x512'));
  for (const icon of manifest.icons) {
    assert.ok(icon.src.startsWith('/') && existsSync(`${root}public${icon.src}`), `${icon.src} 파일 없음`);
    if (icon.type === 'image/png') {
      const bytes = readFileSync(`${root}public${icon.src}`);
      assert.equal(bytes.subarray(1, 4).toString(), 'PNG');
      assert.equal(`${bytes.readUInt32BE(16)}x${bytes.readUInt32BE(20)}`, icon.sizes);
    }
  }
});

test('화면: manifest와 아이콘을 연결하고 기기 승인 상태를 확인 전으로 표시한다', () => {
  assert.match(html, /<link rel="manifest" href="\/manifest\.webmanifest">/u);
  assert.match(html, /<meta name="theme-color" content="#101a28">/u);
  assert.match(html, /<title>BYTE BACK 내 자료실<\/title>/u);
  assert.match(html, /<p id="device-status" data-status="unverified">확인 전<\/p>/u);
  assert.ok(html.includes(DISCLAIMER));
  assert.match(html, /import \{ setDeviceStatus, viewState \} from '\/app-shell\.js';/u);
  assert.match(html, /id="offline-banner"[^>]*hidden/u);
  // 처음 화면에는 보호 자료 영역이 없다: 메모 추가 화면은 숨김, 목록에는 안내 문구뿐
  assert.match(html, /<section class="editor" id="editor"[^>]*hidden>/u);
  assert.match(html, /<ul id="notes"[^>]*><li>로그인하면 이 기기의 승인 상태를 확인합니다\./u);
  for (const text of [html, shell, worker, read('public/offline.html')]) {
    assert.doesNotMatch(text, /기기 확인 완료|기기 승인 완료|설치했으므로 승인/u);
  }
});

test('화면이 부르는 서버 경로는 기존과 같고 새 브라우저 저장소 호출이 늘지 않았다', () => {
  const paths = new Set([...html.matchAll(/['"`](\/api\/[A-Za-z0-9_/${}.]*)['"`]/gu)].map((match) => match[1]));
  assert.deepEqual([...paths].sort(), ['/api/auth/login', '/api/auth/logout', '/api/auth/refresh', '/api/device/approve',
    '/api/device/request', '/api/device/status', '/api/notes', '/api/notes/${note.id}', '/api/ops/summary']);
  // 11단계부터 로그인 토큰도 어떤 브라우저 저장소에도 쓰지 않는다 (sessionStorage 사용을 없앴다).
  for (const text of [html, codeOnly(shell)]) {
    assert.doesNotMatch(text, /sessionStorage|localStorage|indexedDB|document\.cookie|\bcaches\./u);
  }
  assert.doesNotMatch(codeOnly(shell), /\bfetch\(|XMLHttpRequest/u, '보조 코드는 서버 요청을 보내지 않음');
});

test('기기 승인 상태: 알 수 없는 값은 확인 전이고 서버 값 하나로만 바뀐다', () => {
  assert.equal(deviceStatusLabel('unverified'), '확인 전');
  assert.equal(deviceStatusLabel('pending'), '승인 대기');
  assert.equal(deviceStatusLabel('approved'), '승인됨');
  assert.equal(deviceStatusLabel('denied'), '거부됨');
  for (const bad of [undefined, null, '', 'installed', 'standalone', 'APPROVED', 'toString', '__proto__', 'constructor', 7, {}]) {
    assert.equal(normalizeDeviceStatus(bad), 'unverified', String(bad));
    assert.equal(deviceStatusLabel(bad), '확인 전', String(bad));
  }
  const page = fakeBrowser();
  assert.equal(setDeviceStatus(page.document, 'approved'), 'approved');
  assert.equal(page.nodes['#device-status'].textContent, '승인됨');
  assert.equal(setDeviceStatus(page.document, 'installed'), 'unverified');
  assert.equal(page.nodes['#device-status'].textContent, '확인 전');
});

test('설치된 앱 화면이어도 기기 승인 상태는 확인 전이고 설치 상태 문구도 승인과 별개라고 밝힌다', () => {
  for (const standalone of [false, true]) {
    const page = fakeBrowser({ standalone });
    startShell(page);
    assert.equal(page.nodes['#device-status'].dataset.status, 'unverified');
    assert.equal(page.nodes['#device-status'].textContent, '확인 전');
    assert.equal(page.nodes['#device-note'].textContent, DEVICE_NOTE);
    assert.match(page.nodes['#install-state'].textContent, standalone ? /설치된 앱 화면/u : /브라우저 탭/u);
    assert.match(page.nodes['#install-state'].textContent, /기기 승인과는 별개/u);
    // 앱 설치 이벤트나 화면 모드가 바뀌어도 승인 상태는 바뀌지 않는다
    page.listeners.appinstalled?.();
    page.listeners.online?.();
    assert.equal(page.nodes['#device-status'].dataset.status, 'unverified');
  }
  assert.doesNotMatch(installStateText({ standalone: true }), /승인됨|확인 완료/u);
  const iosStyle = fakeBrowser();
  iosStyle.navigator.standalone = true;
  startShell(iosStyle);
  assert.match(iosStyle.nodes['#install-state'].textContent, /설치된 앱 화면/u);
  assert.equal(iosStyle.nodes['#device-status'].dataset.status, 'unverified');
});

test('오프라인 안내: 연결이 끊기면 안내를 보이고 돌아오면 숨기며 서비스 워커를 등록한다', () => {
  const page = fakeBrowser({ online: false });
  startShell(page);
  assert.equal(page.nodes['#offline-banner'].hidden, false);
  assert.equal(page.nodes['#offline-banner'].textContent, OFFLINE_NOTE);
  page.listeners.online();
  assert.equal(page.nodes['#offline-banner'].hidden, true);
  assert.equal(page.nodes['#offline-banner'].textContent, '');
  page.listeners.offline();
  assert.equal(page.nodes['#offline-banner'].hidden, false);
  assert.deepEqual(page.registered, [['/sw.js', { scope: '/' }]]);
  // 서비스 워커를 쓸 수 없는 브라우저에서도 오류 없이 시작한다
  const plain = fakeBrowser();
  delete plain.navigator.serviceWorker;
  assert.doesNotThrow(() => startShell(plain));
  const failing = fakeBrowser();
  failing.navigator.serviceWorker.register = () => { throw new Error('등록 실패'); };
  assert.doesNotThrow(() => startShell(failing));
});

function loadWorker({ fetchImpl }) {
  const handlers = {};
  const cached = new Map();
  const deleted = [];
  const context = {
    self: { addEventListener: (type, handler) => { handlers[type] = handler; }, clients: { claim: async () => 'claimed' } },
    caches: {
      open: async () => ({ addAll: async (urls) => { urls.forEach((url) => cached.set(url, `cached:${url}`)); } }),
      match: async (url) => cached.get(url),
      keys: async () => ['old-cache', 'vault-offline-v1'],
      delete: async (key) => { deleted.push(key); return true; },
    },
    fetch: fetchImpl, URL, Promise,
  };
  vm.runInNewContext(worker, context);
  return { handlers, cached, deleted };
}
const navigation = (url, mode = 'navigate') => {
  const event = { request: { mode, url }, response: undefined, respondWith(promise) { this.response = promise; } };
  return event;
};

test('서비스 워커: 화면 이동이 실패할 때만 오프라인 안내를 돌려주고 /api/와 자료 요청은 건드리지 않는다', async () => {
  const sw = loadWorker({ fetchImpl: async () => { throw new TypeError('network'); } });
  let waited;
  sw.handlers.install({ waitUntil: (promise) => { waited = promise; } });
  await waited;
  assert.deepEqual([...sw.cached.keys()].sort(), ['/icon-192.png', '/icon.svg', '/offline.html']);
  let activated;
  sw.handlers.activate({ waitUntil: (promise) => { activated = promise; } });
  assert.equal(await activated, 'claimed');
  assert.deepEqual(sw.deleted, ['old-cache']);

  const offline = navigation('https://example.test/');
  sw.handlers.fetch(offline);
  assert.equal(await offline.response, 'cached:/offline.html');
  for (const [url, mode] of [['https://example.test/api/notes', 'navigate'], ['https://example.test/api/notes/abc', 'cors'],
    ['https://example.test/data.json', 'same-origin'], ['https://example.test/', 'no-cors']]) {
    const event = navigation(url, mode);
    sw.handlers.fetch(event);
    assert.equal(event.response, undefined, `${mode} ${url}`);
  }
  const online = loadWorker({ fetchImpl: async () => 'page-from-network' });
  const normal = navigation('https://example.test/');
  online.handlers.fetch(normal);
  assert.equal(await normal.response, 'page-from-network');
});

test('서비스 워커 소스: 응답을 저장하는 코드와 /api 처리, 로그인 정보 접근이 없다', () => {
  assert.doesNotMatch(worker, /\.put\(|cache\.add\(|caches\.add\(/u);
  assert.doesNotMatch(worker, /Authorization|authorization|token|localStorage|sessionStorage|indexedDB/u);
  assert.match(worker, /request\.mode !== 'navigate'/u);
  assert.match(worker, /startsWith\('\/api\/'\)/u);
  const shellList = /const SHELL = \[(.*?)\];/u.exec(worker)?.[1] ?? '';
  assert.match(shellList, /OFFLINE_URL/u);
  assert.doesNotMatch(shellList, /data\.json|index\.html|\/api/u);
});

test('오프라인 화면: 외부 요청과 스크립트가 없고 기기 승인을 단정하지 않는다', () => {
  const offline = read('public/offline.html');
  assert.doesNotMatch(offline, /<script|https?:\/\//u);
  assert.match(offline, /기기 승인은 서버와 판정기가 정하며/u);
  assert.match(offline, /<a href="\/">/u);
});

test('배포 헤더: 기존 nosniff를 유지하고 manifest와 서비스 워커 헤더를 더한다', () => {
  const config = JSON.parse(read('vercel.json'));
  const find = (source) => config.headers.find((rule) => rule.source === source)?.headers ?? [];
  assert.deepEqual(find('/(.*)'), [{ key: 'X-Content-Type-Options', value: 'nosniff' }]);
  assert.deepEqual(find('/manifest.webmanifest'), [{ key: 'Content-Type', value: 'application/manifest+json' }]);
  assert.deepEqual(find('/sw.js'), [{ key: 'Cache-Control', value: 'no-cache' }, { key: 'Service-Worker-Allowed', value: '/' }]);
  assert.equal(config.outputDirectory, 'public');
});

test('새 정적 파일에는 키 모양 글자가 없다', () => {
  // 키 모양 패턴은 실행할 때 조립해 저장소 파일에 키 형태 글자가 남지 않게 합니다.
  const shapes = [`sb_${['sec', 'ret'].join('')}_[A-Za-z0-9_-]{6,}`, `s${'k'}-[A-Za-z0-9]{20,}`, 'eyJ[A-Za-z0-9_-]{12,}\\.eyJ', `PRIV${'ATE KEY'}`];
  const pattern = new RegExp(shapes.join('|'), 'u');
  for (const name of ['index.html', 'app-shell.js', 'sw.js', 'offline.html', 'manifest.webmanifest', 'icon.svg']) {
    assert.doesNotMatch(read(`public/${name}`), pattern, name);
  }
});
