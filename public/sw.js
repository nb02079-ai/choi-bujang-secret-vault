// 오프라인 안내 화면만 보여 주는 서비스 워커입니다.
// 화면 이동(navigate) 요청이 네트워크 오류로 실패할 때만 미리 저장해 둔 오프라인 안내를 돌려줍니다.
// /api/ 요청과 자료는 가로채지도 저장하지도 않으므로, 로그인 전후의 자료가 섞이거나 오래된 응답이 남지 않습니다.
// 이 파일은 기기 승인과 무관합니다. 기기 승인은 서버와 판정기가 정합니다.
const CACHE = 'vault-offline-v1';
const OFFLINE_URL = '/offline.html';
const SHELL = [OFFLINE_URL, '/icon-192.png', '/icon.svg'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.mode !== 'navigate') return;
  if (new URL(request.url).pathname.startsWith('/api/')) return;
  event.respondWith(fetch(request).catch(() => caches.match(OFFLINE_URL)));
});
