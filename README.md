# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. `/data.json`에는 같은 가상 메모가 공개됩니다. 이 공개 상태를 확인하는 것이 1단계의 출발점입니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 2단계: 자료를 코드 밖으로 옮김

가상 메모 네 건은 Supabase 학습용 테이블 `vault_notes`에 있고, 공개 `/data.json`의 `notes`는 비어 있습니다. 화면은 `/api/notes` 서버 함수(`api/notes.mjs`)를 통해 메모를 읽습니다. 함수는 Vercel 환경변수 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`를 읽어 서버 안에서만 Supabase를 호출합니다. 두 값은 Vercel 프로젝트의 Settings → Environment Variables에 학생이 직접 넣고, 코드·Git·README에는 적지 않습니다. 환경변수를 새로 넣거나 바꾼 뒤에는 Redeploy해야 함수에 반영됩니다. 테이블을 만드는 SQL은 로컬 `supabase/` 폴더에 있고 Git에는 올리지 않습니다.

**남아 있는 약점:** `/api/notes`는 아직 공개 주소입니다. 로그인 확인이 없어서 누구나 이 주소를 직접 열어 메모 네 건을 읽을 수 있습니다. 비밀키가 브라우저로 나가지는 않지만, 자료 접근을 막은 것은 아닙니다. 3단계 이후 로그인과 허용 경로로 막아야 합니다.

**현재 작동하는 기능 (2단계 저장점):** 화면 `/`은 `/api/notes`에서 가상 메모 네 건을 읽어 카드로 보여 줍니다. `/data.json`은 `"notes": []`입니다. `/api/notes`는 GET만 받고 다른 방식은 405로 거부합니다.

**다시 실행하는 방법:**
1. Supabase SQL Editor에 로컬 `supabase/001_notes.sql`을 붙여 넣고 실행해 `vault_notes`를 만듭니다. 이 파일은 Git에 없으므로 다시 필요하면 학생의 로컬 사본이나 코딩 도구에 다시 만들게 합니다.
2. Vercel의 Environment Variables에 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`가 Production에 있는지 확인하고, 바꿨다면 Redeploy합니다.
3. 배포 주소 `https://choi-bujang-secret-vault-hazel.vercel.app`에서 화면과 `/data.json`, `/api/notes`를 확인합니다. 로컬에서 가상 화면만 볼 때는 `npm run build -- --local`을 씁니다. 이는 배포나 심판 접수를 증명하지 않습니다.

### 가상 메모 문장이 공개 파일에 남았는지 확인하는 절차

메모를 옮긴 뒤에는 현재 배포 파일과 GitHub 최신 파일에서 가상 메모 문장이 사라졌는지 직접 검색합니다. 검색어는 메모에 공통으로 들어 있는 문장 `실습용 가상`입니다. 배포 주소는 Vercel 프로젝트의 도메인입니다.

1. 현재 배포 파일: `https://choi-bujang-secret-vault-hazel.vercel.app`의 `/`, `/index.html`, `/data.json`, `/aleph.json`을 각각 열어 검색어가 없는지 봅니다. 터미널에서는 `curl -s <주소> | grep -c '실습용 가상'`이 `0`이어야 합니다. `/data.json`에는 1단계 시작 틀 확인 표시 `SAMPLE_NOTE_1`(`sampleMarker`)도 없어야 하므로 `curl -s <주소>/data.json | grep -c SAMPLE_NOTE_1`도 `0`이어야 합니다. 2단계부터 `data.json`에 이 표시가 있으면 빌드가 실패합니다.
2. GitHub 최신 파일: 푸시 뒤 `git fetch origin`을 하고 `git grep -n '실습용 가상' origin/r5-rc1`을 실행합니다. 결과가 없어야 합니다. 로컬 `supabase/`는 Git에 올리지 않으므로 이 검색에 나오지 않습니다.
3. 서버 함수는 이 절차의 대상이 아닙니다. `/api/notes`는 메모를 돌려주는 것이 맞는 동작입니다. 그 대신 아래 약점으로 따로 기록합니다.

**검색 결과 (2026-10-06, 커밋 `5366a1d` 배포 뒤)**

| 대상 | 검색 결과 |
|---|---|
| 배포 `/`, `/index.html`, `/data.json`, `/aleph.json` | 모두 0건 |
| GitHub `origin/r5-rc1` 최신 파일 | 일치 없음 |
| 옛 공개 커밋 `0f9a3c9` | `data.json`, `public/data.json`에 메모 4건이 그대로 남아 있음 |
| GitHub `origin/main`, 태그 `r5-rc1` | 같은 두 파일에 메모 문장이 남아 있음 |
| 옛 배포 `…-hpt87519f-nb02079-ai.vercel.app` | Vercel 로그인 보호가 걸려 있어 내용을 확인하지 못함 |

**과거 노출은 해소되지 않았습니다.** 최신 파일에서 문장이 사라진 것은 앞으로의 공개를 줄인 것일 뿐입니다. 옛 공개 커밋과 옛 배포가 남아 있는 한, 이미 공개되었던 가상 메모를 누군가 받아 갔을 가능성은 없어지지 않습니다. 가상 자료라서 피해가 크지 않지만, 해소됐다고 적지 않습니다.

**공개 API의 남은 약점:** `/api/notes`는 로그인 확인이 없는 공개 주소라서, 누구나 GET으로 열어 메모 네 건을 읽을 수 있습니다. 2026-10-06에 실제로 열어 네 건이 읽히는 것을 확인했습니다. 정적 파일 검색이 0건이어도 이 주소로는 같은 내용이 읽힙니다. 3단계 이후 로그인과 허용 경로로 막아야 합니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
