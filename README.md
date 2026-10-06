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

가상 메모 네 건은 Supabase 학습용 테이블 `vault_notes`에 있고, 공개 `/data.json`은 `{"notes": []}`입니다. 1단계 시작 틀 확인 표시(`SAMPLE_NOTE_1`)도 `/data.json`에서 뺐고, 2단계부터 `data.json`에 메모나 이 표시가 있으면 빌드가 실패합니다. 서버 함수는 Vercel 환경변수 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`를 읽어 서버 안에서만 Supabase를 호출합니다. 두 값은 Vercel 프로젝트의 Settings → Environment Variables에 학생이 직접 넣고, 코드·Git·README에는 적지 않습니다. 환경변수를 새로 넣거나 바꾼 뒤에는 Redeploy해야 함수에 반영됩니다. 테이블을 만드는 SQL은 로컬 `supabase/` 폴더에 있고 Git에는 올리지 않습니다.

2단계에서 남았던 약점(`/api/notes`가 로그인 없이 읽히는 공개 주소)은 3단계에서 로그인 검사로 닫았습니다. 아래 3단계를 보세요.

### 가상 메모 문장이 공개 파일에 남았는지 확인하는 절차

메모를 옮긴 뒤에는 현재 배포 파일과 GitHub 최신 파일에서 가상 메모 문장이 사라졌는지 직접 검색합니다. 검색어는 메모에 공통으로 들어 있는 문장 `실습용 가상`입니다. 배포 주소는 Vercel 프로젝트의 도메인입니다.

1. 현재 배포 파일: `https://choi-bujang-secret-vault-hazel.vercel.app`의 `/`, `/index.html`, `/data.json`, `/aleph.json`을 각각 열어 검색어가 없는지 봅니다. 터미널에서는 `curl -s <주소> | grep -c '실습용 가상'`이 `0`이어야 합니다. `/data.json`에는 1단계 시작 틀 확인 표시 `SAMPLE_NOTE_1`(`sampleMarker`)도 없어야 하므로 `curl -s <주소>/data.json | grep -c SAMPLE_NOTE_1`도 `0`이어야 합니다.
2. GitHub 최신 파일: 푸시 뒤 `git fetch origin`을 하고 `git grep -n '실습용 가상' origin/r5-rc1`을 실행합니다. 결과가 없어야 합니다. 로컬 `supabase/`는 Git에 올리지 않으므로 이 검색에 나오지 않습니다.
3. 서버 함수 `/api/notes`는 로그인한 사용자에게만 메모를 돌려주므로 이 검색의 대상이 아닙니다. 그 접근은 3단계의 점검과 약점으로 따로 기록합니다.

**검색 결과 (2026-10-06, 커밋 `5366a1d` 배포 뒤)**

| 대상 | 검색 결과 |
|---|---|
| 배포 `/`, `/index.html`, `/data.json`, `/aleph.json` | 모두 0건 |
| GitHub `origin/r5-rc1` 최신 파일 | 일치 없음 |
| 옛 공개 커밋 `0f9a3c9` | `data.json`, `public/data.json`에 메모 4건이 그대로 남아 있음 |
| GitHub `origin/main`, 태그 `r5-rc1` | 같은 두 파일에 메모 문장이 남아 있음 |
| 옛 배포 `…-hpt87519f-nb02079-ai.vercel.app` | Vercel 로그인 보호가 걸려 있어 내용을 확인하지 못함 |

**과거 노출은 해소되지 않았습니다.** 최신 파일에서 문장이 사라진 것은 앞으로의 공개를 줄인 것일 뿐입니다. 옛 공개 커밋과 옛 배포가 남아 있는 한, 이미 공개되었던 가상 메모를 누군가 받아 갔을 가능성은 없어지지 않습니다. 가상 자료라서 피해가 크지 않지만, 해소됐다고 적지 않습니다.

## 3단계: 로그인과 메모 추가·수정·삭제

**현재 작동하는 기능 (3단계 저장점):**
- 화면 `/`에 Supabase Auth 이메일·비밀번호 로그인·로그아웃이 있습니다. 공식 `@supabase/supabase-js`를 쓰고, 화면 코드에는 공개용 Project URL과 publishable key만 있습니다. 로그인 실패 이유는 화면에 표시합니다.
- 서버는 요청의 `Authorization: Bearer` 토큰을 틀의 `src/verify-login.mjs`로만 검사합니다. 토큰이 없거나 검사에 실패하면 자료 저장소를 읽지 않고 401을 돌려줍니다. 요청에 실린 `userId`·`role`·`owner_id`는 쓰지 않고, 사용자 ID는 검사를 통과한 토큰에서만 얻습니다.
- 로그인한 사용자는 가상 메모를 추가·수정·삭제할 수 있습니다. 추가할 때 `owner_id`는 서버가 확인한 사용자 ID로 저장합니다. 제목은 1~100자, 내용은 2000자 이하입니다. 코드는 `api/notes/index.mjs`, `api/notes/[id].mjs`, 공용 로직 `src/notes-api.mjs`입니다.
- 검사에 쓴 발급자 정보(`issuer`, `audience`, `jwksUrl`, 비밀 제외)는 `aleph.config.json`의 `identityProvider`에 있습니다.

| 경로 (`allowedRoutes`) | 동작 | 응답 |
|---|---|---|
| `GET /api/notes` | 로그인 사용자의 메모 목록 | `[{id,title,body}]` |
| `POST /api/notes` | 추가. `{id?,title,body}`, id는 UUID이고 없으면 서버가 만듦 | 201 `{id}` |
| `GET /api/notes/:id` | 한 건 | `{id,title,body}`, 없으면 404 |
| `PUT /api/notes/:id` | 수정 `{title,body}` | 200 `{id}`, 없으면 404 |
| `DELETE /api/notes/:id` | 삭제 | 200 `{id}`, 지운 뒤 GET은 404 |

**다시 실행하는 방법:**
1. 2단계의 Supabase 테이블과 Vercel 환경변수 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`를 준비합니다.
2. Supabase 대시보드의 Authentication → Users → Add user에서 가상 A 계정을 만들고 Auto Confirm User를 체크합니다. 실제 이메일은 쓰지 않습니다. 계정의 비밀번호는 학생이 직접 정하고 코드·Git·채팅에 적지 않습니다.
3. 배포 주소에서 A로 로그인해 메모를 추가·수정·삭제하고, 로그아웃하면 폼과 목록이 사라지는지 봅니다. 로컬 시험은 `npm run test:r5`이며 가짜 검사기와 메모리 저장소를 쓰므로 실제 Supabase 동작을 증명하지 않습니다.

**실제로 보낸 요청의 결과 (2026-10-06, 커밋 `469aaef` 배포 뒤):** 로그인 토큰 없이 보낸 `GET`·`POST /api/notes`와 `GET`·`PUT`·`DELETE /api/notes/:id`는 모두 401이었습니다. 엉터리 토큰이나 위조한 `x-user-id`·`owner_id`를 실어도 401이었고, `PATCH`는 405였습니다. 이는 학생의 자기 점검이며 심판의 판정이 아닙니다. `npm run bundle`의 `src/attack-check.mjs`가 같은 요청을 다시 보냅니다.

**아직 확인하지 못했거나 실행하지 않은 것:**
- 정상 A 로그인 뒤 실제 Supabase에서 추가·수정·삭제가 되는지는 코드로 실행하지 않았습니다. 계정 정보를 코드에 넣지 않기 위해서이며, 학생이 브라우저에서 직접 확인해야 합니다(`attack-check`의 `logged_in_crud`는 미실행).
- B가 A의 메모에 접근할 수 있는지는 점검하지 않았습니다(`cross_user_access`는 미실행).

**남아 있는 약점:** 소유자 검사가 없습니다. 로그인은 신원 확인일 뿐이라서, 로그인한 B가 A의 메모 `id`를 알면 읽고 고치고 지울 수 있습니다. `owner_id`는 저장만 하고 아직 비교하지 않습니다. `owner_id`가 비어 있는 처음 네 건의 메모도 목록에는 나오지 않지만 `id`를 알면 같은 방식으로 접근됩니다. 4단계에서 기록하고 막습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
