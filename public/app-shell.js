// 설치형 웹앱 화면의 보조 코드입니다. 기기 승인 상태 표시, 설치 상태 안내, 오프라인 안내만 맡습니다.
// 기기 승인은 서버와 판정기가 정합니다. 이 파일은 앱 설치 여부, 화면 모드, 연결 상태로 승인 상태를 바꾸지 않습니다.
// 로그인 토큰, 기기 키, 그 밖의 값을 브라우저 저장소(localStorage, sessionStorage, IndexedDB, 쿠키)에 쓰지 않습니다.

export const DEVICE_STATUS_LABELS = Object.freeze({
  unverified: '확인 전',
  pending: '승인 대기',
  approved: '승인됨',
  denied: '거부됨',
});

// 알 수 없는 값은 승인됨으로 보이지 않게 모두 확인 전으로 돌립니다.
export const normalizeDeviceStatus = (status) => (Object.hasOwn(DEVICE_STATUS_LABELS, status) ? status : 'unverified');
export const deviceStatusLabel = (status) => DEVICE_STATUS_LABELS[normalizeDeviceStatus(status)];

export const DEVICE_NOTE = '기기 승인은 서버와 판정기가 정합니다. 앱을 설치했다는 표시만으로 이 기기가 확인된 것은 아닙니다.';
export const OFFLINE_NOTE = '오프라인입니다. 자료를 불러올 수 없고 로그인과 메모 요청은 연결된 뒤에 다시 시도해 주세요.';

// 설치 상태는 안내용입니다. 어떤 값이어도 기기 승인 상태와 연결하지 않습니다.
export function installStateText({ standalone }) {
  return standalone ? '앱 설치 상태: 설치된 앱 화면으로 열려 있습니다. 기기 승인과는 별개입니다.'
    : '앱 설치 상태: 브라우저 탭으로 열려 있습니다. 브라우저 메뉴의 앱 설치로 설치할 수 있으며, 기기 승인과는 별개입니다.';
}

// 로그인 여부와 서버가 알려 준 기기 승인 상태로 화면의 어느 부분을 보일지 정합니다.
// 보호 자료(메모 추가 화면, 메모 목록)는 서버가 승인됨이라고 알려 준 경우에만 열립니다.
// 버튼, 앱 설치, 화면 모드는 이 함수의 입력이 아니므로 승인 여부를 바꾸지 못합니다.
const STATE_MESSAGES = Object.freeze({
  signedOut: '로그인하면 이 기기의 승인 상태를 확인합니다. 승인된 기기에서만 내 메모가 보입니다.',
  unverified: '이 기기는 아직 승인되지 않았습니다. 승인되기 전에는 자료를 볼 수 없습니다. 아래에서 승인을 요청하세요.',
  pending: '승인 대기 중입니다. 승인되기 전에는 자료를 볼 수 없습니다. 이미 승인된 기기에서 로그인해 승인 코드를 입력해 주세요.',
  denied: '이 기기는 승인되지 않았거나 폐기되었습니다. 자료를 볼 수 없습니다. 운영자에게 문의해 주세요.',
});
export function viewState({ signedIn, status }) {
  const known = signedIn ? normalizeDeviceStatus(status) : 'unverified';
  const approved = Boolean(signedIn) && known === 'approved';
  return {
    status: known,
    showEditor: approved,
    showNotes: approved,
    showActions: Boolean(signedIn),
    showRequest: Boolean(signedIn) && known === 'unverified',
    showApprove: approved,
    message: approved ? '' : STATE_MESSAGES[signedIn ? known : 'signedOut'],
  };
}

// 서버가 승인 상태를 알려 주는 경로가 생기면 이 함수 하나로만 표시를 바꿉니다.
export function setDeviceStatus(doc, status) {
  const box = doc.querySelector('#device-status');
  if (!box) return 'unverified';
  const next = normalizeDeviceStatus(status);
  box.textContent = deviceStatusLabel(next);
  box.dataset.status = next;
  return next;
}

export function startShell({ document: doc, window: win, navigator: nav } = globalThis) {
  setDeviceStatus(doc, 'unverified');
  const note = doc.querySelector('#device-note');
  if (note) note.textContent = DEVICE_NOTE;

  const standalone = Boolean(win?.matchMedia?.('(display-mode: standalone)')?.matches) || nav?.standalone === true;
  const install = doc.querySelector('#install-state');
  if (install) install.textContent = installStateText({ standalone });

  const banner = doc.querySelector('#offline-banner');
  const showConnection = (online) => {
    if (!banner) return;
    banner.hidden = online;
    banner.textContent = online ? '' : OFFLINE_NOTE;
  };
  showConnection(nav?.onLine !== false);
  win?.addEventListener?.('online', () => showConnection(true));
  win?.addEventListener?.('offline', () => showConnection(false));

  // 서비스 워커는 오프라인 안내 화면만 보여 줍니다. 등록에 실패해도 화면은 그대로 동작합니다.
  try { nav?.serviceWorker?.register('/sw.js', { scope: '/' })?.catch?.(() => {}); } catch { /* 등록하지 못해도 계속합니다 */ }
}

if (typeof document !== 'undefined' && typeof window !== 'undefined') startShell();
