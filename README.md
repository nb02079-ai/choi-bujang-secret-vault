# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비공개 설정값를 넣지 마세요.

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

가상 메모 네 건은 Supabase 학습용 테이블 `vault_notes`에 있고, 공개 `/data.json`은 `{"notes": []}`입니다. 1단계 시작 틀 확인 표시(`SAMPLE_NOTE_1`)도 `/data.json`에서 뺐고, 2단계부터 `data.json`에 메모나 이 표시가 있으면 빌드가 실패합니다. 서버 함수는 Vercel 환경변수 `SUPABASE_URL`과 서버 비공개 `SUPABASE_SECRET_KEY`를 읽어 서버 안에서만 Supabase를 호출합니다. 두 값은 Vercel 프로젝트의 Settings → Environment Variables에 학생이 직접 넣고, 코드·Git·README에는 적지 않습니다. 환경변수를 새로 넣거나 바꾼 뒤에는 Redeploy해야 함수에 반영됩니다. 테이블을 만드는 SQL은 로컬 `supabase/` 폴더에 있고 Git에는 올리지 않습니다.

2단계에서 남았던 약점(`/api/notes`가 로그인 없이 읽히는 공개 주소)은 3단계에서 로그인 검사로 닫았습니다. 아래 3단계를 보세요.

### 가상 메모 문장이 공개 파일에 남았는지 확인하는 절차

메모를 옮긴 뒤에는 현재 배포 파일과 GitHub 최신 파일에서 가상 메모 문장이 사라졌는지 직접 검색합니다. 검색어는 메모에 공통으로 들어 있는 문장 `실습용 가상`입니다. 배포 주소는 Vercel 프로젝트의 도메인입니다.

1. 현재 배포 파일: `https://choi-bujang-vault-nb02079-ai.vercel.app`의 `/`, `/index.html`, `/data.json`, `/aleph.json`을 각각 열어 검색어가 없는지 봅니다. 터미널에서는 `curl -s <주소> | grep -c '실습용 가상'`이 `0`이어야 합니다. `/data.json`에는 1단계 시작 틀 확인 표시 `SAMPLE_NOTE_1`(`sampleMarker`)도 없어야 하므로 `curl -s <주소>/data.json | grep -c SAMPLE_NOTE_1`도 `0`이어야 합니다.
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
- 화면 `/`에 Supabase Auth 이메일·비밀번호 로그인·로그아웃이 있습니다. 공식 `@supabase/supabase-js`를 쓰고, 화면 코드에는 공개용 Project URL과 공개용 키만 있었습니다(5단계에서 화면 밖으로 옮겼습니다. 아래 5단계 참고). 로그인 실패 이유는 화면에 표시합니다.
- 서버는 요청의 `Authorization: Bearer` 토큰을 틀의 `src/verify-login.mjs`로만 검사합니다. 토큰이 없거나 검사에 실패하면 자료 저장소를 읽지 않고 401을 돌려줍니다. 요청에 실린 `userId`·`role`·`owner_id`는 쓰지 않고, 사용자 ID는 검사를 통과한 토큰에서만 얻습니다.
- 로그인한 사용자는 가상 메모를 추가·수정·삭제할 수 있습니다. 추가할 때 `owner_id`는 서버가 확인한 사용자 ID로 저장합니다. 제목은 1~100자, 내용은 2000자 이하입니다. 코드는 `api/notes/index.mjs`, `api/notes/[id].mjs`, 공용 로직 `src/notes-api.mjs`입니다.
- 검사에 쓴 발급자 정보(`issuer`, `audience`, `jwksUrl`, 비밀 제외)는 `aleph.config.json`의 `identityProvider`에 있습니다.

| 경로 (3단계 당시 `allowedRoutes`. 8단계에서 목록·추가 두 줄을 뺌) | 동작 | 응답 |
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

3단계 당시의 한계(정상 로그인 뒤 추가·수정·삭제를 코드로 실행하지 않은 것, 소유자 검사가 없어 B가 A의 메모 `id`로 접근할 수 있었던 것)는 4단계에서 소유자 검사로 막았습니다. 아래 4단계를 보세요.

## 4단계: 로그인해도 내 자료만 보이게 합니다

**현재 작동하는 기능 (4단계 저장점):**
- 서버(`src/notes-api.mjs`)는 검증된 사용자 ID와 DB 행의 `owner_id`를 코드에서 직접 비교합니다. 읽기(목록·한 건)·추가·수정·삭제를 모두 본인 메모로 제한하고, 허용되지 않은 요청은 기본 거부합니다.
- 목록은 본인 메모만 돌려줍니다. 한 건 조회·수정·삭제에서 남의 메모, 주인이 없는 메모, 없는 메모는 모두 같은 404입니다. 존재 여부를 알려 주지 않기 위해서입니다.
- 추가할 때 `owner_id`는 검증된 사용자 ID로만 저장합니다. URL·본문의 `owner_id`는 믿지 않습니다.
- 수정은 기존 행이 본인 것이어야 하고 새 행의 소유자도 본인이어야 합니다. 본문이 다른 `owner_id`(다른 사람·null·숫자·빈 값)를 내세우면 쓰기 전에 403으로 거부합니다. 저장소에 보내는 수정·삭제에도 `owner_id=본인` 조건을 다시 겁니다.
- 한 건 응답은 `{id,title,body}`, 수정 본문은 `{title,body}`입니다. `allowedRoutes` 5개는 실제 처리하는 방식·경로와 정확히 같고, 시험이 이를 확인합니다(8단계에서 3개로 줄였습니다. 아래 8단계 참고).
- DB 쪽: 로컬 `supabase/003_rls_least_privilege.sql`(Git에 올리지 않음)이 `vault_notes`의 기존 권한을 `REVOKE ALL … FROM PUBLIC, anon, authenticated`로 회수하고 `authenticated`에 `SELECT·INSERT·UPDATE·DELETE`만 줍니다. RLS 정책은 `SELECT`·`DELETE`는 기존 행(USING), `INSERT`는 새 행(WITH CHECK), `UPDATE`는 둘 다 `auth.uid() = owner_id`일 때만 허용합니다. 앱 서버는 RLS를 우회하는 서버 비공개 설정값로 접속하므로, 서버 코드의 소유자 비교가 1차 방어이고 GRANT·RLS는 키 없이 DB에 직접 닿는 경로를 막는 2차 방어입니다.
- 기존 가상 메모의 소유자 연결은 로컬 `supabase/002_assign_owners.sql`로 했습니다. `과제`·`포트폴리오`·`아침 리추얼`은 A, `B의 시험 메모`는 B 소유이고, `훈련 행정 자료`는 주인이 없어 누구도 접근하지 못합니다.

**다시 실행하는 방법:**
1. Supabase 대시보드의 Authentication → Users → Add user에서 가상 A·B 계정을 만들고 Auto Confirm User를 체크합니다. 실제 이메일은 쓰지 않고 비밀번호는 학생이 직접 정합니다.
2. SQL Editor에서 `002_assign_owners.sql`의 자리표시자를 두 계정 이메일로 바꿔 실행하고, 그다음 `003_rls_least_privilege.sql`을 `[1]` 적용 전 점검 → `[2]` 적용 → `[3]` 적용 후 점검 순서로 따로 실행합니다. 두 SQL은 Git에 없으므로 필요하면 코딩 도구에 다시 만들게 합니다.
3. 배포 주소에서 A로 로그인해 자기 메모를 읽고 추가·수정·삭제하고, B로도 같게 해 봅니다. 각자 목록에는 자기 메모만 보여야 합니다.
4. 로컬 시험은 `npm run test:r5`입니다. 가짜 검사기와 메모리 저장소를 쓰므로 실제 Supabase 동작을 증명하지 않습니다.

**학생이 SQL Editor에서 실행해 보고한 적용 후 점검 결과:** `role_table_grants`는 `authenticated`만 `DELETE, INSERT, SELECT, UPDATE`이고 PUBLIC·anon 행이 없습니다. `has_table_privilege`는 `anon`이 없음, `authenticated`가 `SELECT, INSERT, UPDATE, DELETE`뿐이고, 서비스 역할은 앱 API가 쓰는 권한을 유지합니다. `anon`에는 컬럼 단위 권한도 없습니다. RLS는 켜져 있고 정책은 네 개이며 모두 `roles={authenticated}`, 조건은 `auth.uid() = owner_id`입니다. 이 값은 학생이 붙여 준 결과이고, 코딩 도구는 DB에 접속하지 않았습니다.

**실제로 보낸 요청의 결과 (2026-10-06, 학생의 자기 점검이며 심판의 판정이 아님):**

| 요청 | 결과 |
|---|---|
| 배포된 페이지에서 읽은 공개 anon 키로 Supabase Data API `GET`(목록·id 조건), `POST`(빈 본문), `PATCH`, `DELETE`(없는 id) | 5건 모두 HTTP 401, `42501` permission denied for table `vault_notes` |
| 로그인 토큰 없이 `GET /api/notes` | HTTP 401 |

`npm run bundle`의 `src/attack-check.mjs`가 위 anon 직접 요청과 3단계의 토큰 없는 요청(`GET`·`POST /api/notes`, `GET`·`PUT`·`DELETE /api/notes/:id`, 가짜 토큰, 위조 `x-user-id`·`owner_id`, `PATCH`)을 다시 보냅니다. anon 직접 요청에는 존재하지 않는 id 조건이나 필수 칸이 빠진 빈 본문만 써서, 권한이 잘못 열려 있어도 자료가 바뀌지 않게 했습니다.

**아직 확인하지 못했거나 실행하지 않은 것:**
- 정상 A·B 로그인 뒤 실제 Supabase에서 각자 자기 메모를 읽고 추가·수정·삭제하는 것, B가 A의 메모를 읽거나 고치거나 지우려다 404·403으로 거부되는 것은 코드로 실행하지 않았습니다. 계정 정보를 코드에 넣지 않기 위해서이며, 서버의 소유자 비교는 로컬 시험(가짜 검사기·메모리 저장소)으로만 확인했습니다. 학생이 브라우저에서 직접 확인해야 합니다(`attack-check`의 `logged_in_own_crud`, `cross_user_access`는 미실행).
- `authenticated` 역할로 Data API에 직접 접근하는 것은 점검하지 않았습니다. 정책은 본인 행만 허용하도록 설계했지만, 심판이 재현할 수 없는 경로라 점수 대상에서 제외됩니다.

**남아 있는 약점:**
- 서버가 RLS를 우회하는 비공개 설정값로 접속하므로, 서버 코드의 소유자 비교에 버그가 있으면 DB의 RLS가 막아 주지 못합니다. 비공개 설정값가 유출되면 모든 메모가 노출됩니다.
- 추가할 때 이미 있는 `id`를 보내면 409가 돌아와, 그 `id`가 어딘가에 있다는 것을 알려 줍니다. UUID라 추측은 어렵지만 작은 신호입니다.
- 주인이 없는 `훈련 행정 자료`는 누구도 읽거나 고칠 수 없는 채로 DB에 남아 있습니다.
- 공개 anon 키는 화면 코드에 있고 권한이 없어 거부되지만, 키가 공개되어 있다는 사실은 그대로입니다.
- `/aleph.json`에는 1단계 시작 틀 확인 표시(`sampleMarker`)가 남아 있습니다. 배포 신원 파일이 설정값을 그대로 적기 때문입니다.
- 2단계에서 적은 과거 노출은 해소되지 않았습니다. 옛 공개 커밋, `origin/main`, 태그 `r5-rc1`에 옛 가상 메모가 남아 있습니다.

## 5단계: 자료 요청을 서버 한곳으로 모읍니다

**현재 작동하는 기능 (5단계 저장점):**
- 브라우저 코드(`public/index.html`)는 Supabase를 직접 부르지 않습니다. `supabase-js`와 Project URL, 공개용 키를 화면에서 모두 없앴습니다. 로그인·토큰 갱신·로그아웃은 서버 함수 `POST /api/auth/login`, `/api/auth/refresh`, `/api/auth/logout`(`src/auth-api.mjs`)이 Supabase Auth로 대신 전달하고, 메모 읽기·추가·수정·삭제는 `callApi()`로 `/api/notes`, `/api/notes/:id`만 부릅니다. 로그인 토큰은 5단계 당시 그 탭의 `sessionStorage`에 두었으나, 11단계부터 화면 메모리에만 둡니다(아래 11단계 참고). 서버 함수는 이메일·비밀번호·토큰을 로그에 남기지 않고, 로그인 실패는 계정 존재 여부를 알리지 않는 같은 문구로 답합니다.
- 로그인 서버 함수는 Vercel 환경변수 `SUPABASE_PUBLISHABLE_KEY`(공개용 키)를 서버에서만 읽습니다. 값은 학생이 Settings → Environment Variables에 직접 넣고, 넣은 뒤 Redeploy해야 합니다. 이 값이 없으면 로그인이 500(서버 설정 미완료)으로 실패합니다. `/api/auth/*`는 자료 API가 아니라서 `allowedRoutes`에 넣지 않았습니다.
- 서버 함수의 로그인 검사, 소유자 비교, 서버 비공개 설정(`SUPABASE_URL`, `SUPABASE_SECRET_KEY`)은 4단계 그대로입니다. `allowedRoutes` 5개도 그대로였습니다(8단계에서 3개로 줄였습니다).
- `aleph.config.json`의 `originalApiUrl`은 쿼리 없는 원본 자료 주소 `https://hcaygyndhpfqrwlfbpqt.supabase.co/rest/v1/vault_notes`입니다. 이 주소를 공개 anon 키로 직접 부르면 거부되어야 하고, 메모가 보이면 안 됩니다. 배포 신원 파일 `/aleph.json`에도 같은 주소가 `originalApiUrl`로 실립니다(5단계부터, 쿼리가 없는 `https://` 경로가 아니면 빌드가 실패합니다). 허용 경로 목록 `allowedRoutes`(`GET /api/notes` 같은 형식, 1개 이상)도 `/aleph.json`에 실리며, 비어 있거나 형식이 다르면 빌드가 실패합니다. `restoreRoute`는 아직 `null`입니다.
- DB 쪽: 로컬 `supabase/004_revoke_direct_access.sql`(Git에 올리지 않음)이 `vault_notes`의 `PUBLIC`·`anon`·`authenticated` 권한을 모두 회수하고, 서비스 역할의 네 권한과 RLS가 남았는지 같은 트랜잭션에서 확인합니다. 003의 RLS 정책 네 개는 지우지 않고 2차 방어로 남깁니다.

**다시 실행하는 방법:**
0. Vercel 프로젝트의 Settings → Environment Variables에 `SUPABASE_PUBLISHABLE_KEY`(Supabase 대시보드의 공개 키)를 직접 넣고 Redeploy합니다. 코드·Git·채팅에는 적지 않습니다.
1. SQL Editor에서 `004_revoke_direct_access.sql`을 `[1]` 적용 전 점검 → `[2]` 적용 → `[3]` 적용 후 점검 순서로 따로 실행합니다. 이 SQL은 Git에 없으므로 필요하면 코딩 도구에 다시 만들게 합니다.
2. 배포 주소에서 A로 로그인해 메모를 읽고 추가·수정·삭제하고, B로도 해 봅니다. 각자 목록에는 자기 메모만 보여야 합니다.
3. 로컬 시험은 `npm run test:r5`, 자기 점검과 제출 묶음은 `npm run bundle`입니다.

**기록 범위:**
- `npm run bundle`의 `src/attack-check.mjs`는 첫 화면에 공개 키 형태의 문자열이 없는지 읽어 보고(`page_no_public_key`), 공개 키가 화면에 없으므로 anon 직접 요청에는 터미널 환경변수 `SUPABASE_PUBLISHABLE_KEY`의 값을 씁니다(결과·로그에 싣지 않습니다). 환경변수가 없으면 그 요청들은 미실행으로 남습니다. 보낸 요청의 결과는 `artifacts/submission.json`에만 남고 이 README에는 적지 않습니다(심판의 판정이 아닙니다). 5단계에서는 토큰 없는 요청, 공개 anon 키로 원본 주소에 직접 보낸 4가지 요청, 원본 주소에서 메모가 보이는지 읽어 보는 요청을 보냅니다.
- 미실행: 로그인 토큰을 실은 원본 주소 직접 요청(`authenticated_direct_rejected`), 정상 A 로그인 뒤 서버 함수 동작(`logged_in_own_crud`), B의 거부(`cross_user_access`). 계정 정보와 토큰을 코드에 넣지 않기 위해서이며 학생이 브라우저에서 직접 확인해야 합니다.
- **학생이 SQL Editor에서 실행해 보고한 004 적용 후 점검 결과:** `role_table_grants`에 `PUBLIC`·`anon`·`authenticated` 행이 없습니다. `has_table_privilege`는 `anon`과 `authenticated`가 모두 `(없음)`이고 서비스 역할은 `SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER`를 유지합니다. `has_any_column_privilege`는 `anon`과 `authenticated` 모두 `(없음)`입니다. RLS는 켜져 있고(`true`) 정책은 4개(`policy_count`)입니다. 이 값은 학생이 붙여 준 결과이고, 코딩 도구는 DB에 접속하지 않았습니다. 적용 전 `[1]` 결과는 받지 않아 대조하지 못했습니다.
- 004 적용 뒤 `authenticated` 토큰으로 원본 주소를 직접 불러 거부되는지는 코드로 실행하지 않았습니다(`authenticated_direct_rejected`는 미실행).

**남아 있는 약점:** 서버가 RLS를 우회하는 비공개 설정값로 접속하므로 서버의 소유자 비교가 유일한 1차 방어이고, 2단계의 과거 노출은 해소되지 않았습니다. 화면에서 공개 키는 없앴고, 5단계 당시 `sessionStorage`에 있던 로그인 토큰(access·refresh)은 11단계에서 화면 메모리로 옮겼습니다. 로그인 요청에 시도 횟수 제한이 없고(Supabase Auth 쪽 제한에 의존), 옛 커밋 기록에는 공개 키가 남아 있습니다. 로그인 서버 함수와 새 화면 코드는 가짜 fetch 시험과 문법 검사만 했고, 실제 Supabase로 로그인해 본 것이 아닙니다.

## 보너스 xdr-01: 무차별 로그인 공격 경보

수업용 Wazuh 모양 경보 묶음 `xdr/fixtures/brute-force.json`(가상 28건)을 읽어 `block`·`alert`·`record`로 나눕니다. 실제 로그가 아니며, 3~5단계 자료실과 `src/decider.mjs`는 건드리지 않았습니다.

**현재 작동하는 기능 (xdr-01 저장점):**
- `xdr/brute-force/decide.mjs`: 단독으로 계산하는 `decide(alert)` 하나만 내보냅니다(import·파일·네트워크 사용 없음). 근거는 MITRE ATT&CK T1110이며, 패턴 3개(`rapid_failures_same_source`, `password_spraying_many_accounts`, `failures_then_success`)가 맨 위 상수로 들어 있고 `patterns.json`과 같은 내용입니다. 확신도(경보가 패턴과 맞는 정도, 0~1)가 0.85 이상이면 `block`, 0.5 이상이면 `alert`, 그 아래는 `record`입니다. 15건·5개 같은 숫자는 MITRE 값이 아니라 이 수업의 학생 기준입니다.
- `xdr/brute-force/read-alerts.mjs`: 확인용으로 시각·주소·계정·수준·설명만 뽑습니다(비밀값처럼 보이는 값은 가림). `decide.mjs`와 서로 불러오지 않습니다.
- `xdr/brute-force/respond.mjs`: `block`만 만료 시각(기본 15분)과 근거 경보 번호가 붙은 거부 규칙으로 넣고, 알림을 `xdr/alerts.log`(Git 제외)에 한 줄씩 쌓습니다. 내부망·보호 주소, 성공이 섞인 경보, 근거 번호가 없는 경보는 규칙으로 만들지 않습니다. 판정기에는 `withBruteForceDeny`로 거부만 더하는 방식으로 꽂으며 기본값은 아무것도 막지 않습니다.

**다시 실행하는 방법:**
1. `npm run xdr:run -- brute-force`: `xdr/brute-force/result.json`을 만듭니다(`counts` 확인).
2. `node xdr/brute-force/respond.mjs`: 경보를 시간 순서대로 다시 흘려 거부 규칙과 알림 로그를 만듭니다. 로그 위치를 바꾸려면 `--log <경로>`를 붙입니다.
3. 시험: `node --test test/xdr-*.test.mjs`

**실제로 실행한 결과 (2026-10-08, 학생의 자기 점검이며 심판의 판정이 아님):**

| 확인 | 결과 |
|---|---|
| `result.json`의 `counts` | block 10, alert 9, record 9 (경보 28건과 일치) |
| 명확한 공격(`bf-01`~`bf-10`) | 모두 `block`, 다시 흘리면 거부 규칙 9개(`bf-02`는 `bf-01`과 같은 주소라 알림만) |
| 애매한 시도(`bf-11`~`bf-19`) | 모두 `alert`, 알림 로그에만 남고 거부 규칙 없음 |
| 정상 이벤트(규칙 수준 3 이하 9건) | 모두 `record`, `block` 0건, 알림 로그에도 없음 |

"정상 이벤트"는 정답표가 없어 규칙 수준 3 이하로 정한 기준입니다.

**아직 연결되지 않았거나 확인하지 못한 것:**
- 판정 요청(`aleph.decision.v1`)에는 주소 필드가 없어, `withBruteForceDeny`의 `addressOf` 기본값은 아무것도 막지 않습니다. 운영 엔진이 요청 밖에서 주소를 알려 주는 연결과 거부 이유 코드 `bruteforce_blocked`의 등록 여부는 확인하지 않았습니다.
- `src/decider.mjs`에는 xdr 연결이 없고 `RULE_IDS`에 `xdr.bruteforce.deny`를 넣지 않았습니다(이 절을 쓴 10월 8일에는 시작 틀 그대로였고, 이후 6~7단계 규칙만 더했습니다). 거부 규칙은 메모리에만 있어 프로세스가 끝나면 사라집니다.
- `bf-11`, `bf-12`, `bf-17`처럼 실패 뒤 성공한 경보는 애매한 사례로 `alert`에 뒀습니다. 로컬 시험과 연습 실행이며 심판 판정이나 실제 접속 차단이 아닙니다.

## 보너스 xdr-02: 웹 주입 경보

수업용 Wazuh 모양 경보 묶음 `xdr/fixtures/web-injection.json`(가상 26건)을 읽어 `block`·`alert`·`record`로 나눕니다. 실제 로그가 아니며, 3~5단계 자료실과 `src/decider.mjs`는 건드리지 않았습니다. 구조는 위 xdr-01(무차별 로그인)과 같습니다.

**현재 작동하는 기능 (xdr-02 저장점):**
- `xdr/web-injection/decide.mjs`: 단독으로 계산하는 `decide(alert)` 하나만 내보냅니다(import·파일·네트워크 사용 없음). 근거는 MITRE ATT&CK T1190이고, 요청 인자 안의 SQL 구문·스크립트 태그·`../`·명령 구분자가 같은 주소에서 5건 이상 반복되면 막기 대상입니다(명령 구분자는 처음 지시한 신호 밖이었으나 학생이 막기 대상으로 추가했습니다). 패턴 6개가 맨 위 상수로 들어 있고 `patterns.json`과 같은 내용입니다. 확신도(경보가 패턴과 맞는 정도, 0~1)가 0.85 이상이면 `block`, 0.5 이상이면 `alert`, 그 아래는 `record`입니다.
- 애매한 시도는 알림까지만 합니다: 한 번뿐인 의심 표기(`single_injection_like_attempt`), 반복 기준 미만, 그리고 Wazuh 규칙 수준 4~9(한 번짜리 의심 이벤트)인 웹 요청 경보(`mid_level_web_request`, 수업 단어만 있는 요청과 평소보다 긴 주소 포함)입니다. 규칙 수준 3 이하(성공·허가된 이벤트)는 기록만 합니다. 수준 구간의 근거는 Wazuh 문서의 규칙 분류표입니다. 5건이라는 숫자는 MITRE·CWE 값이 아니라 이 수업의 학생 기준입니다.
- `xdr/web-injection/read-alerts.mjs`: 확인용으로 시각·주소·계정·수준·설명만 뽑습니다(비밀값처럼 보이는 값은 가림). `decide.mjs`와 서로 불러오지 않습니다.
- `xdr/web-injection/respond.mjs`: `block`만 만료 시각(기본 15분)과 근거 경보 번호가 붙은 거부 규칙(`xdr.webinjection.deny`)으로 넣고, 알림을 `xdr/alerts.log`(Git 제외)에 한 줄씩 쌓습니다. 내부망·보호 주소, 근거 번호가 없는 경보는 규칙으로 만들지 않습니다. 판정기에는 `withWebInjectionDeny`로 거부만 더하는 방식으로 꽂으며 기본값은 아무것도 막지 않습니다.

**다시 실행하는 방법:**
1. `npm run xdr:run -- web-injection`: `xdr/web-injection/result.json`을 만듭니다(`counts` 확인).
2. `node xdr/web-injection/respond.mjs`: 경보를 시간 순서대로 다시 흘려 거부 규칙과 알림 로그를 만듭니다. 로그 위치를 바꾸려면 `--log <경로>`를 붙입니다.
3. 시험: `node --test test/xdr-*.test.mjs`

**실제로 실행한 결과 (2026-10-08, 학생의 자기 점검이며 심판의 판정이 아님):**

| 확인 | 결과 |
|---|---|
| `result.json`의 `counts` | block 8, alert 9, record 9 (경보 26건과 일치) |
| 명확한 공격(SQL·스크립트·`../`·명령 구분자 반복, `wi-01`~`wi-08`) | 모두 `block`, 다시 흘리면 거부 규칙 7개(`wi-02`는 `wi-01`과 같은 주소라 알림만) |
| 애매한 시도(규칙 수준 4~9, `wi-09`~`wi-17` 9건) | 모두 `alert`, 알림 로그에만 남고 거부 규칙 없음 |
| 정상 이벤트(규칙 수준 3 이하 9건) | 모두 `record`, `block` 0건, 알림 로그에도 없음 |

"정상 이벤트"는 정답표가 없어 규칙 수준 3 이하로 정한 기준입니다.

**아직 연결되지 않았거나 확인하지 못한 것:**
- 판정 요청(`aleph.decision.v1`)에는 주소 필드가 없어, `withWebInjectionDeny`의 `addressOf` 기본값은 아무것도 막지 않습니다. 운영 엔진이 요청 밖에서 주소를 알려 주는 연결과 거부 이유 코드 `webinjection_blocked`의 등록 여부는 확인하지 않았습니다(등록부는 이 저장소에 없고 운영 측이 가집니다. 확인 방법은 `docs/DECIDER_REQUEST.md`의 "구현 전 확인" 2번을 따릅니다).
- `src/decider.mjs`에는 xdr 연결이 없고 `RULE_IDS`에 `xdr.webinjection.deny`를 넣지 않았습니다(이 절을 쓴 10월 8일에는 시작 틀 그대로였고, 이후 6~7단계 규칙만 더했습니다). 거부 규칙은 메모리에만 있어 프로세스가 끝나면 사라집니다.
- 수업 경보의 `data.url`에는 실제 공격 문자열 대신 문서용 표식(`doc-sql-…` 등)이 있어 표식과 실제 공격 모양을 둘 다 찾습니다. 한 번뿐인 의심 표기는 URL에 단서가 없어 설명 문구(따옴표, 구분 문자 등)와 Wazuh 규칙 수준에 의존하므로, 설명이나 수준이 바뀌면 놓칠 수 있습니다. 심판 정답표는 볼 수 없어서, 수준 4~9를 모두 알림으로 보는 것은 심판의 `X02_AMBIGUOUS_NOT_ALERT`·`X02_RECORD_MISMATCH` 안내를 보고 세운 추정이며 재제출로 확인해야 합니다.
- 로컬 시험과 연습 실행이며 심판 판정이나 실제 접속 차단이 아닙니다.

## 6단계: 등록한 기기만 자료실에 들어옵니다

**현재 작동하는 기능 (판정기 규칙 하나):**
- `src/decider.mjs`의 `decide(request)`는 엔진이 확인해 준 `request.deviceRegistered`가 `true`일 때만 `allow`(이유 코드 `approved`)를 돌려줍니다. `false`, 값 없음, 그 밖의 값은 `deny`와 이유 코드 `device_not_registered`입니다. 규칙 이름은 `device_registered`이고 `RULE_IDS`에 있습니다.
- 계약에 없는 `request.device`, `request.identity` 같은 값은 쓰지 않습니다. 자료실 화면과 서버 함수, 3~5단계 기능은 바꾸지 않았습니다.

**확인 순서:**
1. 터미널에서 이 폴더로 이동합니다. 이번 확인에는 따로 설치할 접속 프로그램이 없습니다.
2. `npm run decider:test`를 실행합니다.
3. 첫 줄 `통과 · 등록 기기의 정상 요청`이 나와야 합니다. 등록된 기기의 가상 요청이 `allow`로 나온다는 뜻입니다.
4. 둘째 줄 `통과 · 미등록 기기의 가상 요청`이 나와야 합니다. 미등록 기기의 가상 요청이 `deny`와 `device_not_registered`로 나온다는 뜻입니다. 여기서 `통과`는 요청이 통과했다는 뜻이 아니라, 거부가 기대대로 나왔다는 뜻입니다. 기대와 다르면 `확인 필요`로 나옵니다.
5. 전체 로컬 시험은 `node --test test/*.test.mjs`입니다.

**기록 범위:** 위 두 건은 가상 요청으로 하는 로컬 연습이며 심판 통과 증거가 아닙니다. 미등록 기기 공격에 대한 판정은 심판이 맡습니다. 이유 코드 `device_not_registered`가 운영 등록부(`allowedReasonCodes`)에 있는지는 이 저장소에서 확인하지 못했습니다.

## 7단계: 평소와 다른 접속은 다시 확인합니다

**현재 작동하는 기능 (판정기 규칙 하나 추가, 6단계 기기 규칙 유지):**
- 입력 검사: `readSignals(request)`는 엔진이 넘긴 `signals`와 `recentEvents`만 읽습니다. `signals.source`가 `judge_fixture`일 때만 지역·네트워크·시각을 받고, `none`이거나 값이 없거나 알 수 없는 출처이면 모두 `null`(알 수 없음)입니다. 정상값으로 채우지 않습니다. 형식이 틀린 항목만 `null`이고, 빈 `recentEvents`는 "사건 없음"으로 구분합니다. `headers`, `geo`, 최상위 `region` 같은 계약 밖 이름은 읽지 않으므로 위조한 클라이언트 값이 접속 정보로 올라가지 않습니다.
- 규칙 `step_up_required`: 시각이 0~5시, 네트워크가 `unusual`, 5분 안의 `risk_signal` 사건 횟수 합이 10 이상, 이 세 조건이 모두 참일 때만 `step_up`(이유 코드 `step_up_required`)입니다. 하나라도 알 수 없으면 작동하지 않습니다. 지역은 단독 근거가 아니며 `deny`로 이어지지 않습니다. 세 조건이 참일 때 `explainStepUp(request)`가 사유 목록(`odd_hour`, `unseen_network`, `burst_read`, 보조 `region_unusual`)을 돌려줍니다.
- 재확인: 엔진이 넘긴 `stepUp.verified === true`이고 `authAgeSeconds`가 0~900 정수이면 `allow`, 아니면 다시 `step_up`입니다.
- 판정 순서: 기기 미등록 `deny`(`device_not_registered`) → 복합 이상 `step_up` → 그 밖에는 `allow`. 응답은 계약의 다섯 항목 그대로입니다.

**확인 순서:**
1. `npm run fixture:7`: `정상 사건: allow`, `복합 이상 사건: step_up`이 나와야 합니다.
2. `npm run decider:test`: 4줄이 모두 `통과`여야 합니다. 복합 이상 접속은 `step_up`, 다시 확인한 복합 이상 접속과 정상 요청은 `allow`, 미등록 기기는 `deny`가 기대 결과입니다.
3. 전체 로컬 시험은 `node --test test/*.test.mjs`입니다.

**기록 범위:**
- 위 확인은 모두 가상 요청으로 하는 로컬 연습이며 심판 판정이나 실제 접속 증거가 아닙니다. `npm run bundle`의 `step_up_required_local` 점검도 같은 성격입니다.
- 새벽 0~5시와 5분 안 10회라는 기준은 이 수업 원고에서 확인하지 못해 제가 정한 가정입니다. 상수는 `src/decider.mjs` 맨 위에 있습니다.
- 현재 실제 경로의 `signals.source`는 `none`이므로 실제 접속에서는 이 규칙이 작동하지 않고 기기 규칙만 적용됩니다.
- **미실행:** 제공 엔진이 같은 내 로그인으로 다시 로그인한 시각을 검증하는 계약을 이 저장소에서 찾지 못했습니다(`docs/DECIDER_REQUEST.md`에는 `stepUp` 값의 형식만 있습니다). 그래서 다시 로그인 전 실제 자료 차단, 재로그인 확인, 새 로그인 뒤 요청 허용은 실행하지 않았습니다(`npm run bundle`에서는 `step_up_required_local`의 `observed`에 미실행으로 적습니다). 토큰 원문은 어디에도 기록하지 않았습니다.
- 이유 코드 `step_up_required`가 운영 등록부(`allowedReasonCodes`)에 있는지 확인하지 못했습니다.

## 8단계: 같은 계정이어도 구역을 나눠 확인합니다

**현재 작동하는 기능 (판정기 구역 규칙 세 개 추가, 6·7단계 규칙 유지):**
- 판정 순서: 기기 미등록 `deny` → 구역 `deny` → 복합 이상 `step_up` → `allow`. 규칙 이름은 `RULE_IDS`의 `device_registered`, `step_up_required`, `zone_route_exact`, `zone_notice_read_only`, `zone_instructor_denied`입니다. 판정기는 `service`, `method`, `route`, `path`만 읽고 쿼리와 역할 값은 읽지 않습니다.
- 내 메모(`notes`): `GET`·`PUT`·`DELETE /notes/:id`만 허용합니다. 메모 전체 목록과 추가(`/notes`), ID가 빈 경로, 깊이가 다른 경로, `..`·`%`·공백이 든 ID, `export`·`search`·`all`·`mine`·`shared`·`recent`·`admin`·`download` 등 기능 이름 32개(`src/decider.mjs`의 `FUNCTION_NAMES`)는 `deny`(이유 코드 `route_not_allowed`)입니다. 심판의 가상 요청은 메모 ID가 UUID가 아닐 수 있으므로 ID 형식은 UUID로 좁히지 않습니다.
- 반 공지(`notices`): `GET /notices`, `GET /notices/:id`만 허용합니다. `POST`·`PUT`·`PATCH`·`DELETE`는 누구에게나 `deny`(`zone_forbidden`)입니다. 판정기 요청에는 역할이 없으므로 강사의 공지 수정은 판정기가 아니라 서버의 관리 경로에서 처리해야 합니다. 이 관리 경로는 아직 없습니다.
- 강사 자료(`instructor`): 모든 방식과 경로를 `deny`(`zone_forbidden`)합니다. 서비스 이름을 바꿔 경로 첫 칸만 `instructor`로 속여도 거부합니다. 알 수 없는 서비스, 경로, 방식도 거부합니다.
- 자료 API(`src/notes-api.mjs`)의 소유자 재대조: 검증된 사용자 ID(`student` 또는 `judge`)와 저장된 `owner_id`를 다시 비교합니다. 남의 메모, 주인 없는 메모, 없는 메모는 모두 같은 404이고, 본문이 다른 `owner_id`를 내세우면 쓰기 전에 403입니다. 강사 권한을 저장하는 곳이 없어서 강사 권한은 항상 거부합니다. 화면 메뉴, 요청 본문, 쿼리, 헤더의 `role`·`owner_id`는 무시하고 이유 코드만 로그에 남깁니다. 로그에는 ID, 토큰, 본문을 싣지 않습니다.
- `aleph.config.json`의 `allowedRoutes`는 판정기가 허용하는 `GET`·`PUT`·`DELETE /api/notes/:id` 세 개로 줄였습니다.

**확인 순서:**
1. `npm run fixture:7`: `정상 사건: allow`, `복합 이상 사건: step_up`이 나와야 합니다.
2. `npm run decider:test`: 모든 줄이 `통과`여야 합니다.
3. `node --test test/*.test.mjs`: 구역 규칙은 `test/decider-zones.test.mjs`, 소유자 재대조는 `test/notes-owner-recheck.test.mjs`가 확인합니다.

**기록 범위와 한계:**
- 위 확인은 가상 요청과 가짜 저장소로 하는 로컬 연습이며 심판 판정이 아닙니다. `npm run bundle`의 `decider_local` 점검도 같은 성격이고, 직접 점검 상한 20개를 맞추려고 기기·추가 확인·구역 연습을 한 항목으로 합쳤습니다.
- **미실행:** A·B 실제 계정의 `cross_user_access`, 환경변수 `SUPABASE_PUBLISHABLE_KEY`가 필요한 anon 직접 요청, 다시 로그인 전 실제 자료 차단과 새 요청 허용은 실행하지 않았습니다.
- **미확인:** 이유 코드 `route_not_allowed`·`zone_forbidden`이 운영 등록부(`allowedReasonCodes`)에 있는지, 서비스 이름 `notices`·`instructor`가 엔진의 값과 같은지, 엔진이 보내는 `route`·`path`가 `/notes/:id`인지 `/api/notes/:id`인지 확인하지 못했습니다. 거부는 어느 경우에도 안전한 방향입니다.
- **남은 약점:** 화면(`public/index.html`)이 부르는 `GET`·`POST /api/notes`가 `allowedRoutes`에 없어 화면의 메모 목록과 추가가 막힐 수 있습니다. 공지와 강사 자료를 처리하는 서버 경로, 강사 권한 저장소, 자원 ID 표시(과정 1/3)는 아직 없습니다. 이 저장점 뒤 배포는 이 문제를 정한 다음에 합니다.

## 9단계: 도플갱어를 찾고 권한을 거둡니다

**현재 작동하는 기능 (탐지 규칙 하나, 8단계 판정기는 그대로):**
- 입력 정리: `src/detect.mjs`의 `readDetectionEvents(events)`는 사건에서 가명 주체(`identity.sub` 또는 `subjectId`, 둘 다 있으면 같아야 함), 기기(`deviceId`, 16자리 소문자 16진수), 요청 종류(`method`), 판정(`decision`), 시각(`at`), 네트워크만 새 객체로 옮깁니다. 값이 없거나 형식이 틀리면 `null`이고 정상값으로 채우지 않습니다. 메모 내용, 토큰, 헤더, 이름 같은 그 밖의 값은 읽지도 복사하지도 출력하지도 않습니다. 네트워크는 `signals.source`가 `judge_fixture`일 때만 읽고 지역은 읽지 않습니다.
- 탐지 규칙 `burst_read`: 같은 (주체, 기기) 쌍의 `GET`이 10분 구간(시작 포함, 끝 제외)에서 120건을 넘고, 그 구간에 `network === "unusual"` 사건이 있거나 네트워크 값이 하나도 없을 때(알 수 없음, `docs/DETECT_EVENTS.md`의 연습 계약과 같음) `{ action: "propose_revocation", reasonCode: "burst_read", subject, device }`를 돌려줍니다. 구간에 네트워크 값이 있는데 `unusual`이 없으면(예: 모두 `usual`) 다량 조회여도 `observe`입니다. 네트워크만 이상하거나 지역만 다른 경우, 정확히 120건도 `observe`입니다. 처음에는 네트워크 값이 없는 사건을 `observe`로 두는 엄격 방식이었으나, 심판의 `S09_NO_PROPOSAL`(복합 의심 사건에 회수 제안 없음)을 받고 이 절충 방식으로 바꿨습니다.
- 대상은 확인된 기기 한 개입니다. 같은 계정의 다른 기기 조회량은 합치지 않으므로 정상 기기는 유지됩니다. 의심 기기가 여럿이면 먼저 나온 한 개만 제안합니다. `deviceId`가 없거나 형식이 틀린 사건은 기기를 추측하지 않고 `device` 없이 `subject`와 이유 코드만 담아 제안하며, 기기 있는 사건과 합산하지 않습니다.
- `detect()`는 제안을 반환값으로만 돌려줍니다. 회수 API를 만들거나 부르지 않고, 기기 권한을 바꾸지 않고, 파일·네트워크·콘솔에 쓰지 않습니다. 접속 허용/거부 응답 형식(`src/decider.mjs`의 5개 항목)과 `RULE_IDS`는 바꾸지 않았습니다.

**확인 순서:**
1. `node --test test/detect-input.test.mjs test/detect-rule.test.mjs`: 입력 정리와 탐지 규칙 시험입니다. 복합 의심 사건만 제안이 나오고 정상 사건은 `observe`여야 합니다.
2. `npm run detect:test`: 6건이 모두 `통과`여야 합니다. 121건과 200건은 제안, 정상 30건·120건·사용자 분리·흩어진 조회는 `observe`가 기대 결과입니다.
3. 전체 로컬 시험은 `node --test test/*.test.mjs`입니다. `npm run bundle`에서는 `detect_local` 점검이 같은 가상 사건을 돌립니다.

**기록 범위와 한계:**
- 위 확인은 모두 가상 사건으로 하는 로컬 연습이며 심판 판정이나 실제 접속 회수가 아닙니다. 실제 회수와 걸린 시간은 심판이 확인합니다. 운영 반 엔진의 사건 전달과 회수 집행이 연결됐다고 쓰지 않습니다.
- **미확인:** 이유 코드 `burst_read`가 운영 등록부(`allowedReasonCodes`)에 있는지, 심판 사건에 `deviceId`가 있는지, 결과의 `device` 항목을 심판이 받는지 확인하지 못했습니다. 심판 사건이 다른 모양이면 제안이 나오지 않을 수 있습니다.
- 10분 구간과 120건은 `docs/DETECT_EVENTS.md`의 연습 계약을 따른 기준입니다.
- 8단계에서 적은 약점(화면의 메모 목록·추가 경로가 `allowedRoutes`에 없음, 공지·강사 자료 서버 경로 없음)은 그대로 남아 있습니다.

## 10단계: 백업에서 자료실을 되살립니다

**현재 작동하는 기능 (10단계 저장점):**
- **정책 사본 비교:** `npm run policy:diff -- --snapshot <사본> --expect-sha256 <기대 지문>`은 침해 전에 검증한 안전 정책 사본과 현재 시험 정책의 차이만 보여 줍니다. 복원할 버전과 변경 범위를 먼저 보이고, 사본이 없거나 검증에 실패하면 아무것도 보이지 않고 중단합니다. 읽기만 합니다.
- **시험 정책 복원:** `npm run policy:restore -- ... --only <항목>`은 `policy/test-policy.json`의 지정한 항목만 사본 값으로 되돌립니다. 처음에는 미리보기만 하고, 출력된 확인 토큰을 `--confirm`으로 넣어야 씁니다. 지정하지 않은 항목은 그대로 두고, 감사 이력 `policy/audit.log`에는 한 줄만 덧붙입니다. 심판이 판정하는 `src/decider.mjs`의 `decide()`는 바꾸지 않습니다.
- **메모 한 건 복원:** 비공개 가상 메모 사본에서 지정한 한 건만 되살리는 경로가 있습니다.

| 서비스 | 경로 | 방식 | 설정 위치 |
|---|---|---|---|
| 자료 API (`notes`) | `/api/notes/:id/restore` | `POST` | `aleph.config.json`의 `restoreRoute`와 `allowedRoutes`, 판정기 `POST /notes/:id/restore` |

- **요청:** `Authorization: Bearer <로그인 토큰>`과 본문 `{ "contentSha256": "<사본의 내용 해시, 소문자 16진수 64자>" }`입니다. 메모 ID는 경로에 넣습니다. 본문과 쿼리, 헤더의 `role`·`owner_id`는 읽지 않고 이유 코드만 기록합니다.
- **응답:** 성공은 `200 { id, restored: true, contentSha256 }`이며 메모 내용은 싣지 않습니다. 남의 사본, 사본 없음, 남의 현재 메모와 겹치는 경우, 잘못된 ID는 모두 같은 `404`입니다. 요청 해시가 사본과 다르거나 사본 내용이 저장된 해시와 다르면 `409`, 해시 형식이 틀리면 `400`, `POST`가 아니면 `405`, 로그인이 없으면 `401`입니다. 쓴 뒤 확인이나 감사 기록에 실패하면 이전 상태로 되돌리고 `500`입니다.
- **대조 순서:** 로그인한 사용자와 사본의 `owner_id` 대조 → 사본 내용 해시 재계산 → 요청 해시와 대조 → 현재 행의 소유자 확인 → 해당 ID 한 건만 쓰기 → 다시 읽어 ID·소유자·내용 해시가 사본과 같은지 확인 → 감사 표에 한 줄 추가. 다른 메모와 기존 감사 기록은 건드리지 않습니다.
- **내용 해시:** 제목 바이트, `0x00`, 내용 바이트를 이어 붙인 값의 SHA-256(소문자 16진수)입니다. `src/notes-api.mjs`의 `contentSha256(title, content)`가 계산합니다.
- **DB 표:** `vault_notes_backup`(사본: `id`, `owner_id`, `title`, `content`, `content_sha256`, `backed_up_at`)과 `vault_restore_audit`(감사: `note_id`, `owner_id`, `content_sha256`, `outcome`, `restored_at`, 제목·내용은 저장하지 않음)입니다. 생성 SQL은 로컬 `supabase/005_backup_restore.sql`(Git에 올리지 않음)이며 학생이 SQL Editor에서 직접 실행합니다. 두 표 모두 RLS를 켜고 `anon`·`authenticated` 권한을 회수하며, 감사 표는 서버 키의 수정·삭제 권한도 회수해 덧붙이기만 가능하게 합니다.
- **제출 묶음 점검:** `npm run bundle`은 `restore_local` 점검 하나를 더합니다. 메모리 저장소와 가상 요청으로 B의 메모 한 건 복원(ID·소유자·내용 해시가 사본과 같은지), A의 요청과 틀린 해시의 거부, 정책 비교를 돌려 보며 심판 판정이 아닙니다. 직접 점검이 20개를 넘을 수 없어 9단계의 `detect_local` 결과는 `decider_local` 항목에 합쳤습니다(이름이 바뀐 점검: `detect_local`은 더 이상 따로 없음).
- **허용 경로 변경:** `allowedRoutes`는 8단계의 3개에 이 경로를 더한 4개입니다. 판정기는 `POST /notes/:id/restore` 한 가지만 새로 허용하며, ID 자리의 `restore`(`/notes/restore`), 깊이가 다른 경로, 다른 방식은 계속 거부합니다.

**확인 순서:**
1. `node --test test/notes-restore.test.mjs`: 메모리 저장소로 시험 계정 B의 메모 한 건 복원을 확인합니다. 복원된 행의 ID·소유자·내용 해시가 사본과 같고, A의 메모와 B의 다른 메모, 기존 감사 기록이 그대로여야 합니다.
2. `node --test test/*.test.mjs`: 전체 시험입니다.
3. 실제 DB 확인(학생이 직접): ① `supabase/005_backup_restore.sql`을 실행해 두 표를 만듭니다. ② 파일 안의 예시 주석을 풀어 시험 계정 B의 메모 한 건을 사본으로 만듭니다. ③ 메모 내용을 바꿔 침해 상태를 만든 뒤 B로 로그인해 `POST /api/notes/<메모 id>/restore`를 사본 해시와 함께 보냅니다. ④ 원래 내용으로 돌아오고 감사 표에 한 줄이 생겼는지, A로 같은 요청을 보내면 `404`인지 봅니다. 로그인 토큰과 비밀값은 코드, Git, 채팅에 적지 않습니다.

**기록 범위와 한계:**
- 위 시험은 가짜 저장소로 하는 로컬 연습이며 심판 판정이나 실제 복원 증거가 아닙니다. 실제 DB에서의 복원과 B 계정 확인은 **미실행**입니다.
- **미확인:** 심판이 복원 경로를 `restoreRoute`와 `allowedRoutes` 중 어디서 읽는지, 요청 본문 모양, 이유 코드, 판정기 허용 경로 추가가 심판 기준에 맞는지, `api/notes/[id]/restore.mjs`가 `api/notes/[id].mjs`와 함께 Vercel에 배포되는지 확인하지 못했습니다.
- 사본을 만드는 시점과 기대 해시를 안전하게 전달하는 절차(침해 전에 해시를 따로 기록해 두는 일)는 이 코드에 없고 학생이 정해야 합니다.
- 자료 전체 복원(여러 건 일괄)은 만들지 않았습니다. 이번 경로는 한 번에 한 건만 복원합니다.

### 복구 뒤 1~9단계의 정상·금지 요청을 다시 확인하는 순서

복구가 끝나면 **자료와 정책이 돌아왔는지**, **이전에 막던 요청이 다시 거부되는지**를 아래 순서로 봅니다. 결과 열에는 2026-10-14에 이 저장소에서 로컬로 실제 실행한 것만 적었고, 실행하지 않은 것은 모두 **미실행**입니다. 로컬 실행은 가짜 저장소와 가상 요청으로 하는 연습이며 심판 판정이나 실제 배포 증거가 아닙니다.

**순서**
1. **정책 차이 확인(읽기만):** `npm run policy:diff -- --snapshot <사본> --expect-sha256 <기대 지문>`을 실행해 복원할 버전과 변경 범위를 먼저 봅니다. 사본이 없거나 검증에 실패하면 여기서 멈춥니다.
2. **시험 정책 복원:** `npm run policy:restore -- --snapshot <사본> --expect-sha256 <기대 지문> --only <항목,항목>`으로 미리보기를 보고, 바뀔 항목이 맞으면 출력된 토큰을 `--confirm`에 넣어 다시 실행합니다. 같은 미리보기를 한 번 더 실행했을 때 `바뀔 항목: 없음`이 나오면 정책이 돌아온 것입니다.
3. **메모 한 건 복원:** `POST /api/notes/:id/restore`를 시험 계정 B의 로그인 토큰과 사본 해시로 요청합니다(순서는 위 "확인 순서" 3번). 응답이 `200`이고, 복원된 행의 ID·소유자·내용 해시가 사본과 같고, 감사 표에 한 줄이 늘고 기존 줄이 그대로이고, A의 메모와 B의 다른 메모가 그대로인지 봅니다.
4. **로컬 시험 전체:** `node --test test/*.test.mjs`를 실행해 모든 시험이 통과하는지 봅니다. 아래 표의 단계별 시험도 여기에 포함됩니다.
5. **연습 실행기:** `npm run decider:test`, `npm run fixture:7`, `npm run detect:test`를 실행해 기대 결과가 나오는지 봅니다.
6. **직접 점검:** 변경을 커밋하고 푸시해 깨끗한 작업 트리가 된 뒤 `npm run bundle`을 실행합니다. 환경변수 `SUPABASE_PUBLISHABLE_KEY`가 있어야 anon 직접 요청 점검이 실행되고, 없으면 해당 항목은 `미실행`으로 남습니다.
7. **배포 확인(학생이 직접):** 배포 반영 뒤 배포 주소에서 A·B 계정으로 아래 표의 "정상"과 "금지" 요청을 보냅니다. 토큰과 비밀값은 코드, Git, 채팅에 적지 않습니다.

**단계별 정상·금지 요청**

| 단계 | 정상 요청 (유지되어야 함) | 금지 요청 (다시 거부되어야 함) | 다시 실행하는 방법 | 2026-10-14 로컬 실행 결과 |
|---|---|---|---|---|
| 1 | 시작 틀의 가상 화면이 뜹니다. | 해당 없음. 1단계의 공개 자료 노출은 2단계에서 닫았습니다. | `npm run build -- --local` | 미실행 |
| 2 | 로그인 뒤 서버 함수로 메모를 읽습니다. | 공개 `/data.json`의 `notes`가 비어 있고, 로그인 없는 `GET /api/notes`가 거부됩니다. | `npm run bundle`의 `static_data_json_empty`·`anonymous_list_rejected`, `node --test test/r5.test.mjs` | `test/r5.test.mjs` 18개 통과 (가짜 저장소). 배포 주소 요청은 미실행 |
| 3 | A가 로그인해 메모를 추가·수정·삭제합니다. | 토큰 없음·가짜 토큰·위조 `userId`는 `401`, `PATCH`는 `405`입니다. | `npm run bundle`의 3단계 점검들, `node --test test/r5.test.mjs` | 위와 같은 18개 통과. 배포 주소 요청과 A 로그인 뒤 실제 추가·수정·삭제는 미실행 |
| 4 | A와 B가 각자 자기 메모를 읽고 고칩니다. | B가 A의 메모를 읽거나 고치거나 지우면 `404`, 소유자 변경은 `403`, 공개 키로 Data API 직접 요청은 거부됩니다. | `node --test test/r5.test.mjs test/notes-owner-recheck.test.mjs`, A·B 계정 확인, anon 직접 요청 점검 | `test/notes-owner-recheck.test.mjs` 9개 통과 (가짜 저장소). A·B 실제 계정 확인(`cross_user_access`)과 anon 직접 요청은 미실행 |
| 5 | 로그인·토큰 갱신·로그아웃이 서버 함수를 거칩니다. | 원본 자료 주소를 직접 부르면 거부되고, 첫 화면에 공개 키가 없고, 로그인 토큰을 실은 원본 직접 요청도 거부됩니다. | `npm run bundle`의 `original_url_no_notes`·`page_no_public_key`·`authenticated_direct_rejected` | 미실행 |
| 6 | 등록한 기기의 가상 요청은 `allow`입니다. | 미등록 기기는 `deny`와 `device_not_registered`입니다. | `npm run decider:test` | 4줄 모두 `통과`, `test/decider-input.test.mjs` 8개 통과 |
| 7 | 정상 접속은 `allow`, 다시 확인한 복합 이상 접속도 `allow`입니다. | 복합 이상 접속(새벽, 처음 보는 네트워크, 짧은 시간의 많은 읽기)은 `step_up`입니다. | `npm run fixture:7`, `npm run decider:test` | `정상 사건: allow`, `복합 이상 사건: step_up`, `test/decider-stepup.test.mjs` 11개 통과. 다시 로그인 전 실제 자료 차단과 새 요청 허용은 미실행 |
| 8 | 자기 메모 한 건의 `GET`·`PUT`·`DELETE`와 반 공지 읽기는 `allow`입니다. | 공지 쓰기, 강사 자료, 메모 전체 목록, 알 수 없는 경로와 기능 이름은 `deny`이고, B가 A의 메모를 요청하면 `404`입니다. | `node --test test/decider-zones.test.mjs test/notes-owner-recheck.test.mjs` | `test/decider-zones.test.mjs` 14개 통과 |
| 9 | 정상 조회(120건 이하, 서로 다른 사용자, 흩어진 조회)는 `observe`입니다. | 10분 구간에 120건을 넘는 복합 의심은 대상 기기와 이유 코드가 있는 `propose_revocation`입니다(제안만 하며 실제 회수는 심판이 확인). | `npm run detect:test`, `node --test test/detect-input.test.mjs test/detect-rule.test.mjs` | `detect:test` 6건 모두 `통과`, `test/detect-input.test.mjs` 8개와 `test/detect-rule.test.mjs` 19개 통과. 실제 회수와 걸린 시간은 미실행 |
| 10 | 복원한 메모 한 건과 복원한 시험 정책이 사본과 같습니다. | 사본과 해시가 다르거나 남의 사본·남의 메모를 요청하면 복원되지 않습니다. | `node --test test/policy-diff.test.mjs test/policy-eval.test.mjs test/policy-restore.test.mjs test/notes-restore.test.mjs` | `policy-diff` 10개, `policy-eval` 5개, `policy-restore` 13개, `notes-restore` 11개 통과. 실제 DB 복원과 B 계정 확인은 미실행 |

**전체 합계:** `node --test test/*.test.mjs`는 181개 중 181개 통과, 실패 0개, 건너뜀 0개였습니다(위 표의 단계별 숫자는 이 안에 겹쳐서 들어 있어 더하면 181이 되지 않습니다).

**미실행 항목과 이유**
- `npm run build -- --local`, `npm run bundle`: 이번 과정에서 실행하지 않았습니다. `npm run bundle`은 커밋하고 푸시한 깨끗한 작업 트리가 필요합니다.
- 환경변수 `SUPABASE_PUBLISHABLE_KEY`가 필요한 anon 직접 요청과 원본 주소 점검.
- A·B 실제 계정과 로그인 토큰이 필요한 항목(`cross_user_access`, 로그인 뒤 추가·수정·삭제, 로그인 토큰을 실은 원본 직접 요청).
- 다시 로그인 전 실제 자료 차단, 재로그인 확인, 새 요청 허용: 제공 엔진의 새 로그인 시각 검증 계약을 찾지 못했습니다.
- 실제 회수와 걸린 시간: 심판이 확인합니다.
- 실제 DB에서의 메모 복원, `005_backup_restore.sql` 실행, 배포 반영 뒤 화면 확인.

## 11단계: 나만의 접속 앱을 완성합니다

**현재 작동하는 기능 (11단계 저장점):**
- **설치형 웹앱 설정:** `public/manifest.webmanifest`에 앱 이름 `BYTE BACK 내 자료실`(짧은 이름 `내 자료실`), 시작 주소 `/`, 화면 모드 `standalone`, 색, 아이콘(`icon-192.png`, `icon-512.png`, `icon.svg`)을 적었습니다. 화면(`public/index.html`)이 이 파일과 아이콘, 테마 색을 연결합니다. 따로 설치할 접속 프로그램은 만들지 않았고, 브라우저의 앱 설치 기능만 씁니다.
- **오프라인 안내:** 연결이 끊기면 화면 위에 안내가 나타나고 돌아오면 사라집니다. `public/sw.js`(서비스 워커)는 화면 이동이 네트워크 오류로 실패할 때만 `public/offline.html`을 보여 줍니다. `/api/` 요청, 자료, 로그인 정보는 가로채거나 저장하지 않고, 캐시에는 오프라인 안내 화면과 아이콘 두 개만 들어갑니다.
- **기기 승인은 서버가 정합니다.** 설치했다는 표시, 화면 모드, 버튼 누름은 승인 상태를 바꾸지 못합니다. 화면의 "기기 승인 상태"는 서버 응답(`확인 전`, `승인 대기`, `승인됨`, `거부됨`)만 따르고, 알 수 없는 값이나 오류는 모두 `확인 전`으로 닫습니다.
- **승인 전에는 보호 자료가 없습니다.** 로그인한 뒤 서버가 `승인됨`이라고 알려 주기 전에는 메모 추가 화면이 숨겨지고 목록에는 안내 문구만 보이며, 자료 요청(`GET /api/notes` 등)도 보내지 않습니다. 서버도 자료 API(`/api/notes`, `/api/notes/:id`, `/api/notes/:id/restore`)에서 승인된 기기가 아니면 `403`(`device_not_approved`)을 돌려줍니다. 승인된 기기에서는 기존 화면과 응답이 그대로입니다.
- **기기 키와 토큰은 브라우저 저장소에 넣지 않습니다.** 로그인 토큰은 화면 메모리에만 있고(새로고침하면 다시 로그인), `sessionStorage`·`localStorage`·`IndexedDB`를 쓰지 않습니다. 기기를 알아보는 값은 서버가 만든 `HttpOnly` 쿠키(`__Host-vault_device`, `Secure`, `SameSite=Strict`)이며 화면 스크립트는 읽을 수 없고, DB(`vault_devices`)에는 그 값의 SHA-256 해시만 저장합니다. 쿠키도 브라우저가 보관하는 값이므로, 카드의 "브라우저 저장소"에 쿠키까지 포함하는 해석이라면 이 방식은 맞지 않습니다.

- **제출 묶음 점검:** `npm run bundle`은 단계 11로 만들어지며, 직접 점검 20개 상한과 글자 수 300자 상한 때문에 판정기·탐지, 메모 복원, 기기 승인 연습 결과를 `local_practice` 한 항목에 합칩니다(이전의 `decider_local`, `restore_local`은 따로 없음). 이 항목은 가짜 저장소와 가상 요청으로 승인 전 자료 요청 `403`, 자기 승인 `403`, 승인 뒤 `200`을 확인하며 심판 판정이 아닙니다.

**기기 승인 흐름** (`src/device-api.mjs`, 자료 API가 아니라서 `allowedRoutes`와 `RULE_IDS`는 바꾸지 않았습니다)

| 서비스 | 경로 | 방식 | 하는 일 |
|---|---|---|---|
| 기기 승인 (`device`) | `/api/device/request` | `POST` | 이 기기의 승인을 요청합니다. `승인 대기` 기록과 승인 코드(8자, 15분 유효)만 만들고 권한은 주지 않습니다. 계정당 대기 요청은 5개까지입니다. |
| 기기 승인 (`device`) | `/api/device/status` | `GET` | 쿠키로 이 기기의 상태를 알려 줍니다. 쿠키가 없거나 다른 계정의 기기이면 `unverified`입니다. |
| 기기 승인 (`device`) | `/api/device/approve` | `POST` `{code}` | 이미 승인된 기기에서 같은 계정으로 로그인한 경우에만 같은 계정의 대기 요청 하나를 승인합니다. |

- 승인은 버튼이 아니라 서버 검사로 정해집니다. 대기 중인 기기가 자기 코드로 승인하려 해도 `403`이고, 다른 계정의 코드, 만료된 코드, 이미 쓴 코드는 같은 `404`입니다. 요청의 `role`·`owner_id`·`status`·`device` 값은 읽지 않고 이유 코드만 기록합니다.
- **첫 기기는 운영자가 DB에서 승인합니다.** 승인된 기기가 없으면 화면에서 승인할 수 없습니다. 순서는 아래 "배포 순서"를 따릅니다.
- `judge` 종류의 로그인 토큰은 기기 검증을 엔진이 맡는다고 보고 자료 API의 기기 검사를 건너뜁니다. 확인하지 못한 가정입니다. 환경변수 `DEVICE_GATE=off`를 넣으면 기기 검사를 끌 수 있고(긴급 복구용), 승인 상태를 읽지 못하면 닫습니다.
- 응답과 로그에는 쿠키 값, 해시, 로그인 토큰, 저장소 키를 싣지 않습니다. 승인 코드는 요청한 기기 화면에만 보입니다.

**배포 순서 (이 순서를 지키지 않으면 배포 직후 자료실이 열리지 않습니다)**
1. Supabase SQL Editor에서 로컬 `supabase/006_devices.sql`(Git에 올리지 않음)을 실행해 `vault_devices` 표를 만듭니다.
2. 코드를 푸시해 배포하고, 서버 환경변수는 기존 값(`SUPABASE_URL`, `SUPABASE_SECRET_KEY`, `SUPABASE_PUBLISHABLE_KEY`)을 그대로 씁니다.
3. 배포된 화면에서 로그인하고 "이 기기 승인 요청"을 눌러 승인 코드를 받습니다(15분 안에 다음을 해야 합니다).
4. SQL Editor에서 `006_devices.sql`의 "첫 기기 승인" 질의를 코드와 사용자 번호를 바꿔 실행합니다.
5. 화면에서 "승인 상태 새로고침"을 누르면 `승인됨`이 되고 기존 메모 화면이 열립니다. 이후 다른 기기는 새 기기에서 요청한 코드를 승인된 기기의 "다른 기기에 표시된 승인 코드" 칸에 입력해 승인합니다.
6. 문제가 생겨 자료실을 급히 열어야 하면 Vercel 환경변수 `DEVICE_GATE`를 `off`로 두고 다시 배포합니다. 이는 기기 검사를 끄는 것이므로 임시 조치입니다.

**확인 순서:**
1. `node --test test/device-api.test.mjs test/pwa-device-flow.test.mjs test/pwa-shell.test.mjs`: 서버의 승인 흐름(요청, 상태, 승인, 거부 사례, 자료 API 차단과 통과)과 화면의 상태별 동작을 가짜 저장소·가짜 서버·가짜 문서로 확인합니다.
2. `node --test test/*.test.mjs`: 전체 시험입니다. 승인된 기기의 기존 자료 요청은 이전과 같은 결과여야 합니다(토큰 없는 요청 `401`, 남의 메모 `404`, 구역 `deny` 등).
3. 배포 반영 뒤 학생이 직접 확인(위 배포 순서 포함): ① 승인 전 기기에서 로그인하면 메모 추가 화면과 목록이 보이지 않고 "승인되기 전에는 자료를 볼 수 없습니다"가 나오는지, 개발자 도구 Network 탭에 `/api/notes` 요청이 가지 않는지 봅니다. ② 승인 요청 뒤 `승인 대기`와 코드가 보이는지 봅니다. ③ 승인된 뒤 `승인됨`과 기존 메모 화면이 열리고 자기 메모를 읽고 추가·수정·삭제할 수 있는지 봅니다. ④ 개발자 도구 Application 탭의 Local/Session Storage에 로그인 토큰이 없고, Cookies에 `__Host-vault_device`가 `HttpOnly`로 보이는지 봅니다. ⑤ 같은 기기에서 다른 계정으로 로그인하면 `확인 전`이 되는지 봅니다. 토큰과 비밀값은 코드, Git, 채팅에 적지 않습니다.

**기록 범위와 한계:**
- 위 시험은 가짜 저장소와 가짜 브라우저로 하는 로컬 연습이며 심판 판정이나 실제 설치·승인 증거가 아닙니다. 임시 서버로 정적 파일이 모두 `200`으로 제공되는 것은 확인했습니다.
- **미실행:** 실제 브라우저의 설치 화면, 서비스 워커 등록, 오프라인 동작, 쿠키 설정과 `HttpOnly` 동작, 두 기기 승인 흐름, `006_devices.sql` 실행, Vercel 배포와 헤더 적용, `api/notes/[id]/restore.mjs`와 `[id].mjs`가 함께 배포되는지, 실제 Supabase 응답 모양.
- **미확인:** 심판이 `judge` 토큰 외의 방식으로 자료 API를 부르는지, 이 앱 수준의 기기 승인을 심판 기준과 어떻게 대조하는지, 엔진의 기기 등록(`deviceRegistered`)과 이 `vault_devices` 표의 관계를 확인하지 못했습니다. 판정기는 `deviceRegistered`만 읽으며 이 표를 읽지 않습니다.
- 한 브라우저에는 기기 쿠키가 하나뿐이라, 같은 기기에서 다른 계정이 승인을 요청하면 새 쿠키로 바뀌어 이전 계정은 다시 승인받아야 합니다. 기기 폐기 화면과 승인 코드 입력 횟수 제한(계정 안의 대기 코드만 대상이라 범위는 좁음)은 만들지 않았습니다. 쿠키 값은 도난되면 그 기기로 쓸 수 있으므로 폐기는 DB에서 `revoked`로 바꿔서만 합니다.
- 로그인 토큰이 화면 메모리에만 있어서 새로고침이나 탭을 닫으면 다시 로그인해야 합니다. 화면의 메모 목록·추가(`GET`·`POST /api/notes`)가 `allowedRoutes`에 없는 8단계부터의 약점도 그대로입니다. 아이콘은 한 가지 그림(고리와 점)의 임시 디자인입니다.

## 12단계: 탈환 작전실을 완성합니다

**현재 작동하는 기능 (12단계 저장점):**
- **탈환 작전실 화면:** 승인된 기기에서 로그인하면 화면 맨 아래에 "탈환 작전실"이 열리고, 서버가 이번에 돌려준 요약을 네 구역(판정기 규칙, 탐지 사건, 회수 상태, 복구 버전)과 "미실행·미기록 안내"로 보입니다. 승인 전, 로그인 전, 로그아웃 뒤에는 작전실이 닫히고 작전실 요청도 보내지 않습니다. `작전실 새로고침`은 서버를 다시 부릅니다.
- **서버 경로 `GET /api/ops/summary`** (`src/ops-api.mjs`, 서비스 `ops`): 로그인과 기기 승인을 요구하고 읽기만 합니다. 자료 API가 아니라서 `allowedRoutes`, 판정기, `RULE_IDS`는 바꾸지 않았습니다. 서버 함수는 10개가 되어 Vercel 무료 한도(12개) 안입니다.
- **확인된 결과와 미실행의 구분:** 화면은 서버 응답의 `confirmed`가 `true`인 구역만 `확인됨`으로 표시하고, 읽지 못한 구역은 `미확인`입니다. 화면은 성공 문구를 스스로 만들지 않으며, 안내문에 "화면의 문구는 통과 근거가 아니며 판정은 심판이 합니다"가 있습니다.

| 구역 | 서버가 읽는 곳 | 화면에 보이는 것 | 보이지 않는 것(미기록·미실행) |
|---|---|---|---|
| 판정기 규칙 | 코드(`describePolicy`, `aleph.config.json`) | 규칙 이름과 개수, 구역 경로·허용 경로 개수, 정책 지문 12자 | 판정 결과(allow·deny) 집계: 판정기가 기록하지 않아 `미기록` |
| 탐지 사건 | 코드(`DETECTION_RULE`) | 탐지 기준(600초, GET 120건 초과, `burst_read`) | 탐지 사건 수: 저장소가 없어 `미기록` |
| 회수 상태 | DB `vault_devices`(본인 계정) | 기기 수와 상태별 수(승인 대기, 대기 만료, 승인됨, 거부됨, 폐기됨), 최근 10건의 가린 기록 | 실제 회수 집행과 걸린 시간: 심판이 확인하므로 `미실행` |
| 복구 버전 | DB `vault_notes_backup`, `vault_restore_audit`(본인 계정) | 사본 수, 복원 횟수, 최근 10건의 가린 기록 | 정책 사본 버전: 로컬 파일이라 서버가 읽지 못해 `미확인` |

- **가린 서버 기록:** 기기와 메모는 번호 앞 8자, 내용 해시는 앞 12자, 시각, 상태·결과만 보입니다. 가상 메모의 제목과 내용, 쿠키 값, 해시 원문, 승인 코드, 소유자·사용자 번호, 전체 번호는 서버가 보내지도 않고 화면이 쓰지도 않습니다. 메모 표는 읽지 않습니다.
- **수치 일치:** 화면의 수치는 서버가 같은 기록에서 센 값이고, 시험이 원본 기록에서 직접 센 값과 화면 숫자, 가린 기록의 줄 수가 같은지 확인합니다. 기록이 읽기 한도(100건)를 넘으면 `이상(일부만 읽음)`으로 알리고 가린 기록은 10건까지만 보입니다.
- 한 표를 읽지 못하면 그 구역만 `미확인`이 되고 나머지는 확인된 값 그대로 보입니다. 작전실 요청이 실패하면 숫자를 보이지 않고 오류 문구만 보입니다.

**확인 순서:**
1. `node --test test/ops-api.test.mjs test/ops-room.test.mjs`: 서버 요약의 수치·마스킹·본인 기록만·읽기 전용·부분 실패·기기 승인 검사와, 실제 서버 코드가 만든 응답을 화면 스크립트에 넣어 화면 숫자와 가린 기록이 맞는지를 확인합니다.
2. `node --test test/*.test.mjs`: 전체 시험입니다. 승인된 기기의 기존 자료 요청은 이전과 같은 결과여야 합니다.
3. 배포 반영 뒤 학생이 직접 확인: ① 승인된 기기에서 로그인하면 작전실이 열리고 `내 기기 N개`와 Supabase `vault_devices`에서 본인 계정 행 수가 같은지 봅니다. ② 메모를 복원한 뒤 `작전실 새로고침`을 눌러 복원 기록이 늘어나는지, SQL Editor의 `vault_restore_audit` 본인 행 수와 같은지 봅니다. ③ 승인 전 기기(또는 다른 계정)에서는 작전실이 열리지 않는지 봅니다. 토큰과 비밀값은 코드, Git, 채팅에 적지 않습니다.

**기록 범위와 한계:**
- 위 시험은 가짜 저장소와 가짜 브라우저로 하는 로컬 연습이며 심판 판정이 아닙니다. 판정 결과, 탐지 사건, 실제 회수와 걸린 시간, 41종 공격 방어 여부는 이 화면이 보여 줄 수 없고 심판이 판정합니다. 실제 브라우저와 실제 Supabase에서의 작전실 동작은 **미실행**입니다.
- 판정(`decide`)과 탐지(`detect`)의 결과를 남기는 저장소는 아직 없습니다. 판정기는 엔진이 호출하는 순수 함수라서 기록을 쓰게 바꾸지 않았습니다.
- 작전실은 로그인한 계정 본인의 기록만 보입니다. 다른 계정이나 전체 총공세 기록은 보이지 않습니다.
- `judge` 종류의 로그인 토큰은 11단계와 같이 기기 검사를 건너뜁니다(확인하지 못한 가정).

### 1~11단계 정상·금지 요청 재확인 표 (과정 3/4)

`npm run recheck`는 1~11단계의 정상 요청과 금지 요청을 다시 실행해 **기대, 실제 결과, 요청 ID, 확인 시각, 출처**를 한 표로 만듭니다(`src/recheck.mjs`, `scripts/recheck.mjs`). 화면의 성공 문구나 사람이 적은 결과가 아니라 요청을 실제로 보내 받은 값만 "실제" 칸에 들어갑니다.

```
npm run recheck
npm run recheck -- --deployed https://배포주소 --out 저장폴더
```

- **출처 열의 뜻 (실측한 대상이 다릅니다):** `핸들러`는 실제 서버 함수 코드를 프로세스 안에서 가짜 저장소로 호출한 결과, `판정기`는 실제 `decide()`·`detect()` 호출 결과, `파일`은 배포 파일을 읽은 결과, `배포`는 배포 주소로 보낸 실제 HTTP 응답입니다. `핸들러`와 `판정기` 행은 코드의 실제 동작을 실측한 것이며 **배포된 시스템과 실제 Supabase를 실측한 것이 아닙니다.**
- **배포 요청은 `--deployed`를 줄 때만 보냅니다.** 토큰 없이 보낼 수 있는 12건(화면 열기, 공개 자료, 토큰 없음·가짜 토큰·`PATCH`의 `401`·`405`, 기기 승인 경로의 `401`, 첫 화면 접속값 검사)만 보내고, 계정 토큰이나 비밀값은 받지 않습니다. 주소는 경로·쿼리·계정 정보가 없는 `https`만 받습니다.
- **요청 ID:** `decide()` 요청은 응답이 같은 요청 ID를 돌려주는지 확인하고, 서버 함수 요청에는 우리가 만든 ID를 `x-request-id` 헤더로 보내 기록합니다. 배포 요청에는 Vercel이 주는 `x-vercel-id`를 함께 적습니다. 서버 함수가 요청 ID를 되돌려 주도록 바꾸지는 않았습니다. 파일을 읽거나 함수를 직접 호출하는 행은 요청 ID 칸이 `-(파일·함수 호출)`입니다.
- **일치 여부는 코드가 비교합니다.** 기대 문구와 실제 문구가 같으면 `일치`, 다르거나 오류·요청 실패이면 `불일치`입니다. 금지 요청은 응답 코드뿐 아니라 거부된 뒤에 저장소가 바뀌지 않았는지(`저장소 변화 없음`)까지 실측합니다. 불일치가 하나라도 있으면 종료 코드가 `1`입니다.
- **미실행은 통과가 아닙니다.** 실행하지 않은 요청은 실제 결과·요청 ID·확인 시각을 `-`로 두고 이유를 적습니다. 대상: 공개 접속값(`SUPABASE_PUBLISHABLE_KEY`)이 필요한 Data API·원본 주소 직접 요청, 로그인 토큰이 필요한 A·B 실제 계정 요청과 교차 접근, 실제 Supabase Auth 로그인, 다시 로그인 전 실제 자료 차단, 실제 회수 집행, 실제 DB 복원, 실제 브라우저의 두 기기 승인 흐름, 그리고 `--deployed`를 주지 않았을 때의 배포 요청입니다.
- **41종 공격은 통과로 처리하지 않습니다.** 목록과 심판 판정이 없어 표 맨 아래에 `선언 41종 · 목록 0건 · 실측 0건 · 미실행 41종`으로만 적습니다. 목록이 생기면 이 도구를 확장해 같은 방식으로 실측해야 합니다.
- `npm run bundle`의 직접 점검은 12단계에서도 19개입니다. 작전실 요약(승인된 기기 `200`, 미승인 `403`)과 재확인 표(불일치 0건)의 로컬 결과는 새 항목 없이 `local_practice` 한 항목에 한 문장으로 합쳤고, 심판 판정이 아니라고 명시합니다.
- 결과는 화면에 표로 찍히고 `artifacts/recheck/`(Git 제외)에 `recheck-날짜시각.md`와 `.json`으로 저장됩니다. 표에는 토큰, 쿠키 값, 해시 원문, 저장소 키, 메모 본문이 없습니다.

**마지막 실행 결과 (2026-10-14, 이 환경):**
- 로컬 실행(`npm run recheck`): 전체 72건 중 실측 50건이 모두 `일치`, 불일치 0건, 미실행 22건(배포 요청 12건과 위 미실행 10건).
- 배포 주소 포함(`--deployed https://choi-bujang-vault-nb02079-ai.vercel.app`): 전체 72건 중 실측 62건이 모두 `일치`, 불일치 0건, 미실행 10건. 배포 요청 12건은 모두 기대한 `200`·`401`·`405`와 접속값 0건이었습니다.
- 2~11단계마다 실측한 정상 요청과 실측한 금지 요청이 하나 이상씩 있습니다(1단계는 금지 요청이 없습니다). 이 결과도 심판 판정이 아니며, 배포 서버에 로그인해 보내는 정상 요청은 계정 토큰이 필요해 **미실행**입니다.

## 설치·실행·중지·복구 안내

학생 판정기, 탐지 규칙, 접속 앱, 자료실을 설치하고 실행하고 멈추고 되살리는 방법입니다. 확인한 범위와 확인하지 못한 범위를 구분해 적었습니다.

### 기준 커밋과 확인 범위

- **검사 기준 커밋: `1f2f702`** (12단계 코드 커밋). 이 안내를 쓰기 전에 이 커밋을 새 폴더에 받아 아래 "재현 순서"의 1~6번을 실제로 실행했습니다. 이 커밋 이후의 변경은 안내 문서(`README.md`)와 12단계 저장점(`aleph.config.json`의 `step`, `src/attack-check.mjs`의 12단계 점검, `test/attack-check-limits.test.mjs`)뿐이며, `git diff --stat 1f2f702 HEAD`로 확인할 수 있습니다. 저장점 커밋도 같은 순서로 새 폴더에서 다시 확인했습니다(결과는 저장점 보고에 적었고 이 문서에는 커밋 번호를 되풀이하지 않습니다).
- 확인 일자와 환경: 2026-10-14, Windows, Node.js v24.21.0, npm 11.19.0. `package.json`은 Node.js 22 이상을 요구합니다.
- **확인하지 못한 것:** Vercel 설정 화면과 Supabase 대시보드 조작, 로그인 계정을 쓰는 요청, 실제 브라우저의 설치·오프라인 동작, 제공 엔진 안쪽 동작, 아래 SQL의 실제 실행. 이런 항목은 해당 위치에 `미실행`으로 표시했습니다.

### 누가 만들었나: 학생 몫과 제공 몫

| 구분 | 무엇 | 출처 |
|---|---|---|
| **제공: ALEPH SDP 엔진** | 신원·기기·경로 확인, 요청을 판정기로 보내는 일, 요청·응답 계약 `aleph.decision.v1`(요청 18개 이름, 응답 5개 이름), 이유 코드 등록부(`allowedReasonCodes`), 심판의 가상 사건과 시간 측정, 실제 접속 회수 집행 | 이 엔진은 학생이 만들지 않았고 이 저장소에도 없습니다. 이 저장소에는 계약 설명 `docs/DECIDER_REQUEST.md`(변경 없음)와 `docs/DETECT_EVENTS.md`만 있습니다. |
| **제공: 운영 측 값** | `aleph.config.json`의 `judgeIssuer`(심판 접수 서버 주소) | 운영 측이 채운 값이며 학생이 바꾸지 않습니다. |
| **제공: 시작 틀(학생이 바꾸지 않음)** | `AGENTS.md`, `docs/DECIDER_REQUEST.md`, `scripts/bundle.mjs`, `scripts/decider-test.mjs`, `scripts/detect-test.mjs`, `scripts/fixture-7.mjs`, `src/verify-login.mjs`, `package-lock.json` | 시작 틀 첫 커밋 `0f9a3c9` 이후 내용이 같습니다. |
| **제공 뼈대를 학생이 채움** | `src/decider.mjs`(시작 틀은 모두 거부), `src/detect.mjs`(시작 틀은 항상 `observe`), `src/attack-check.mjs`, `public/index.html`, `scripts/build-public.mjs`, `scripts/deployment-identity.mjs`, `aleph.config.json`, `vercel.json`, `package.json`, `.gitignore`, `docs/DETECT_EVENTS.md`, `test/r5.test.mjs`, `data.json`, `public/data.json` | `0f9a3c9`에서 시작해 단계마다 학생이 지시해 고쳤습니다. |
| **제공: 수업 자료** | `scripts/xdr-run.mjs`, `xdr/README.md`, `xdr/fixtures/*.json`, `test/xdr-run.test.mjs` | main 브랜치에서 가져온 커밋 `812e8f1`입니다. |
| **학생 몫: 판정기 규칙 5개** | `src/decider.mjs`의 `device_registered`, `step_up_required`, `zone_route_exact`, `zone_notice_read_only`, `zone_instructor_denied` | 6~8단계 |
| **학생 몫: 탐지 규칙** | `src/detect.mjs`의 `burst_read`와 `propose_revocation` 제안 | 9단계 |
| **학생 몫: 자료실** | `api/notes/*`, `api/auth/*`, `src/notes-api.mjs`, `src/auth-api.mjs`, DB 표 | 2~5단계 |
| **학생 몫: 접속 앱** | `public/`(화면, manifest, 서비스 워커, 오프라인 화면, 아이콘), `api/device/*`, `src/device-api.mjs` | 11단계 |
| **학생 몫: 복구와 점검** | `src/policy-*.mjs`, 메모 복원 경로, `src/ops-api.mjs`, `public/ops-room.js`, `src/recheck.mjs`, `scripts/*.mjs` 중 새로 만든 것 | 10, 12단계 |
| **학생 몫: 보너스 경보 모듈** | `xdr/brute-force/*`, `xdr/web-injection/*` | xdr-01, xdr-02 |

학생 몫의 코드는 학생이 단계별로 지시하고 코딩 도구(Claude Code)가 작성했으며 학생이 계획을 승인한 뒤 반영했습니다. 코드의 시험은 학생이 실행할 수 있는 로컬 연습이며 심판 판정이 아닙니다.

### 필요한 것

- Node.js 22 이상과 npm. 따로 설치하는 접속 프로그램은 없습니다.
- GitHub 저장소(`aleph.config.json`의 `repoUrl`), 그 저장소에 연결한 Vercel 프로젝트, 학습용 Supabase 프로젝트.
- 로그인용 가상 계정(실제 이메일을 쓰지 않습니다). 계정의 비밀번호는 학생이 직접 정하고 코드, Git, 채팅에 적지 않습니다.

### 설치

1. **받기:** `git clone <저장소 주소>`로 받고, 재현할 때는 `git checkout 1f2f702`로 검사 기준 커밋에 맞춥니다. 최신 상태가 필요하면 브랜치 `r5-rc1`을 그대로 씁니다.
2. **의존 패키지:** 폴더 안에서 `npm install`. 설치되는 것은 `@supabase/supabase-js`와 `jose`뿐입니다. (확인: 오류 없이 끝났고 `found 0 vulnerabilities`였습니다.)
3. **DB 표 만들기 (`미실행`):** 새로 받은 저장소에는 `supabase/` 폴더가 없습니다(샘플 데이터가 들어 있어 Git에 올리지 않습니다). Supabase 대시보드의 SQL Editor에 아래를 붙여 실행합니다. 모든 표는 서버 비공개 설정값으로만 접근하고 `anon`·`authenticated`는 접근하지 못합니다. 이 SQL은 이 환경에서 실행해 보지 못했습니다.

```sql
create table if not exists public.vault_notes (
  id         uuid primary key default gen_random_uuid(),
  owner_id   uuid,
  title      text not null,
  content    text not null,
  created_at timestamptz not null default now()
);
create table if not exists public.vault_notes_backup (
  id             uuid primary key,
  owner_id       uuid not null,
  title          text not null,
  content        text not null,
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  backed_up_at   timestamptz not null default now()
);
create table if not exists public.vault_restore_audit (
  id             bigint generated always as identity primary key,
  note_id        uuid not null,
  owner_id       uuid not null,
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  outcome        text not null,
  restored_at    timestamptz not null default now()
);
create table if not exists public.vault_devices (
  id             uuid primary key default gen_random_uuid(),
  owner_id       uuid not null,
  secret_sha256  text not null unique check (secret_sha256 ~ '^[0-9a-f]{64}$'),
  status         text not null default 'pending' check (status in ('pending', 'approved', 'denied', 'revoked')),
  request_code   text,
  expires_at     timestamptz,
  created_at     timestamptz not null default now(),
  decided_at     timestamptz,
  decided_by     text
);
create index if not exists vault_devices_owner_status on public.vault_devices (owner_id, status);

alter table public.vault_notes          enable row level security;
alter table public.vault_notes_backup   enable row level security;
alter table public.vault_restore_audit  enable row level security;
alter table public.vault_devices        enable row level security;
revoke all on table public.vault_notes         from public, anon, authenticated;
revoke all on table public.vault_notes_backup  from anon, authenticated;
revoke all on table public.vault_restore_audit from anon, authenticated;
revoke all on table public.vault_devices       from anon, authenticated;
-- 복원 감사 표는 서버 키로도 고치거나 지울 수 없게 해서 덧붙이기만 가능하게 합니다.
revoke update, delete, truncate on table public.vault_restore_audit from service_role;
```

   가상 메모는 화면에서 로그인한 뒤 학생이 직접 추가합니다(`owner_id`는 서버가 로그인한 계정으로 채웁니다). 사본 표(`vault_notes_backup`)에 사본을 넣는 방법은 아래 "복구" 3번에 있습니다.
4. **환경 변수 (`미실행`):** Vercel 프로젝트의 Settings 아래 Environment Variables에서 학생이 직접 입력하고, 입력한 뒤 다시 배포(Redeploy)합니다. **이 문서와 Git, 채팅에는 값을 적지 않습니다.** 이름과 쓰임만 적습니다.

| 이름 | 쓰이는 곳 | 비고 |
|---|---|---|
| `SUPABASE_URL` | 서버 함수(자료실, 기기 승인, 작전실) | Supabase 프로젝트 주소 |
| `SUPABASE_SECRET_KEY` | 서버 함수만 | 서버 전용 키. 화면, 응답, 로그에 나오지 않습니다. |
| `SUPABASE_PUBLISHABLE_KEY` | 로그인 서버 함수(`/api/auth/*`) | 서버에서만 읽습니다. 화면 코드에는 넣지 않습니다. 직접 요청 점검(`npm run bundle`)을 터미널에서 실행할 때도 같은 이름의 환경변수를 씁니다. |
| `DEVICE_GATE` | 서버 함수(선택) | `off`이면 기기 승인 검사를 끕니다. 긴급할 때만 쓰고 평소에는 설정하지 않습니다. |
| `POLICY_SNAPSHOT_SHA256` | 터미널의 `policy:diff`·`policy:restore`(선택) | 정책 사본의 기대 지문입니다. Vercel에는 필요 없습니다. |

   `VERCEL_*`로 시작하는 값은 Vercel이 주는 것이라 건드리지 않습니다.
5. **Vercel 설정 (`미실행`):** 저장소를 연결하고 `vercel.json`이 정한 대로 빌드 명령 `npm run build`, 출력 폴더 `public`을 씁니다. 서버 함수는 10개라서 Vercel 무료 한도(12개) 안입니다.
6. **첫 기기 승인:** 승인된 기기가 없으면 화면에서 승인할 수 없습니다. 이 README의 11단계 절 "배포 순서"를 따릅니다(`supabase/006_devices.sql`의 질의는 위 `vault_devices` 표에 대한 `update` 문입니다).

### 실행

- **판정기와 탐지는 따로 실행하는 서버가 아닙니다.** 학생은 `src/decider.mjs`의 `decide(request)`와 `src/detect.mjs`의 `detect(events)` 함수를 제공했고, 이 함수를 부르는 것은 ALEPH SDP 엔진(제공)입니다. 학생이 시작하거나 멈출 판정기 프로세스는 없습니다.
- **로컬 연습과 점검** (모두 한 번 실행하고 끝납니다):

| 명령 | 하는 일 | 정상 결과 |
|---|---|---|
| `node --test test/*.test.mjs` | 전체 로컬 시험 | 242개 통과 |
| `npm run decider:test` | 판정기 가상 요청 4건 | 4줄 모두 `통과` |
| `npm run fixture:7` | 정상·복합 이상 사건 비교 | `정상 사건: allow`, `복합 이상 사건: step_up` |
| `npm run detect:test` | 탐지 가상 사건 6건 | 6줄 모두 `통과` |
| `npm run build -- --local` | 공개 자료 복사 | 복사 메시지 |
| `npm run recheck` | 1~11단계 정상·금지 요청 재확인 표 | 불일치 0건(위 12단계 절 참고) |
| `npm run policy:diff`, `npm run policy:restore` | 정책 사본 비교와 복원(복구 절 참고) | 아래 복구 절 |
| `npm run bundle` | 제출 묶음 만들기 | 단계, 커밋, 규칙 수, 직접 점검 수 |

- **`npm run bundle`의 조건:** 커밋하지 않은 파일이 없어야 하고, Git 설정의 `origin`이 `aleph.config.json`의 `repoUrl`과 같은 GitHub 주소여야 하며, Git 제외 파일 `bundle-notes.json`이 있어야 합니다. 그래서 로컬 경로로 받은 사본에서는 실행하지 않았습니다. 이 명령은 비밀값 패턴(개인키 머리글, `sb_secret_`, `sk-`, JWT 형태, `Bearer` 토큰)이 있으면 실패하고, 단계·커밋·규칙 이름·허용 경로·점검 결과만 묶습니다.
- **접속 앱과 자료실:** 배포 주소를 브라우저로 엽니다. 로그인하고 기기 승인을 받은 뒤에만 메모 화면과 탈환 작전실이 열립니다. 앱 설치는 브라우저 메뉴의 앱 설치를 쓰고, 설치했다는 표시는 기기 승인과 별개입니다. 서버 함수를 로컬에서 띄우는 명령은 만들지 않았습니다(Vercel 명령줄 도구가 필요하고 설치하지 않기로 했습니다).

### 중지

- **로컬:** 위 명령은 모두 실행이 끝나면 종료됩니다. 계속 떠 있는 프로그램이 없어서 로컬에서 멈출 것이 없습니다.
- **접속 앱과 자료실을 멈추는 방법** (약한 것부터):
  1. **한 기기만:** 위 `vault_devices` 표에서 그 기기 행의 `status`를 `revoked`로 바꿉니다. 폐기된 기기는 `거부됨`으로 보이고 자료 요청이 `403`입니다(코드 시험으로 확인, 실제 DB에서는 `미실행`).
  2. **한 계정:** Supabase 대시보드의 Authentication에서 사용자를 정지하거나 삭제합니다(`미실행`).
  3. **자료 API 전체:** Vercel 환경변수 `SUPABASE_URL` 또는 `SUPABASE_SECRET_KEY`를 지우고 다시 배포합니다. 서버 함수는 자료를 읽지 않고 `500`(서버 설정이 아직 끝나지 않았습니다)으로 응답합니다(코드와 시험으로 확인, 실제 배포에서는 `미실행`). 다시 열려면 값을 되돌리고 다시 배포합니다.
  4. **배포 자체:** Vercel 대시보드에서 배포를 내리거나 프로젝트를 삭제합니다. 되돌리기 어려우니 마지막 수단입니다(`미실행`).
- `DEVICE_GATE=off`는 중지가 아니라 **기기 검사를 끄는 것**입니다. 급할 때 자료실을 열려는 임시 조치이며 평소에는 설정하지 않습니다.
- 탐지 함수의 `propose_revocation`은 제안만 반환합니다. 실제 회수와 걸린 시간은 제공 엔진과 심판이 확인하므로 학생이 이 저장소에서 멈추거나 집행할 수 없습니다.

### 복구

1. **코드가 잘못되었을 때:** `git log`로 안정 커밋을 확인합니다(10단계 `d48fc8e`, 11단계 `8ae6d98`, 12단계 코드 `1f2f702`). 잘못된 커밋은 `git revert <커밋>`으로 되돌리고(기록을 지우는 `git reset --hard`는 쓰지 않습니다) 푸시한 뒤 Vercel이 다시 배포하게 합니다. Vercel 대시보드에서 이전 배포로 되돌리는 방법도 있으나 이 환경에서 확인하지 못했습니다.
2. **안전 정책이 바뀌었을 때:** 침해 전에 검증해 둔 정책 사본이 있어야 합니다.
   `npm run policy:diff -- --snapshot <사본> --expect-sha256 <기대 지문>`으로 복원할 버전과 변경 범위만 확인합니다(아무것도 바꾸지 않습니다). 이어서 `npm run policy:restore -- --snapshot <사본> --expect-sha256 <기대 지문> --only <항목,항목>`의 미리보기를 확인하고, 바뀔 항목이 맞으면 출력된 토큰을 `--confirm`에 붙여 다시 실행합니다. 로컬 시험 정책 파일만 바뀌며 심판이 판정하는 코드와 운영 정책은 바뀌지 않습니다.
3. **메모가 바뀌었을 때:** 침해 전에 `vault_notes_backup`에 메모 한 건씩 사본을 넣어 두어야 하고 내용 해시를 따로 적어 둡니다(해시는 제목 바이트, `0x00`, 내용 바이트를 이어 붙인 값의 SHA-256입니다). 사본은 SQL로 만듭니다(`<메모 id>`와 `<사용자 번호>`는 학생이 채웁니다).

```sql
insert into public.vault_notes_backup (id, owner_id, title, content, content_sha256)
select n.id, n.owner_id, n.title, n.content,
       encode(sha256(convert_to(n.title, 'UTF8') || '\x00'::bytea || convert_to(n.content, 'UTF8')), 'hex')
from public.vault_notes n
where n.id = '<메모 id>' and n.owner_id = '<사용자 번호>'
on conflict (id) do nothing;
```

   복원은 해당 계정으로 로그인한 승인된 기기에서 `POST /api/notes/<메모 id>/restore`에 본문 `{ "contentSha256": "<사본 해시>" }`를 보냅니다. `200`이면 그 한 건만 되살아나고 `vault_restore_audit`에 한 줄이 늘어납니다. 사본이 없거나 해시가 다르면 복원하지 않습니다(실제 DB에서는 `미실행`).
4. **기기 승인이 꼬였을 때:** `vault_devices`의 상태를 SQL로 확인하고 `revoked`로 폐기하거나, 새 기기를 만들어 승인된 기기에서 코드를 입력합니다(README의 11단계 절).
5. **복구 뒤 확인:** `npm run recheck`를 실행해 불일치가 0건인지 봅니다. 배포 주소를 함께 주면 토큰 없는 배포 요청도 실측합니다. 계정 토큰이 필요한 항목은 `미실행`으로 남습니다.
6. **비밀값이 노출되었다고 의심될 때:** 해당 키를 Supabase나 Vercel 대시보드에서 새로 발급해 교체하고 다시 배포합니다. 값은 채팅에 붙이지 않습니다. Git 기록에 올라갔다면 기록 정리가 필요하며 이는 이 문서에서 다루지 않습니다.

### 비밀값을 다루는 방식

- 저장소, 제출 묶음, 이 README에는 비밀값이 없습니다. 환경변수 이름과 쓰임만 적었습니다. `.gitignore`가 `.env`, `.env.*`, `supabase/`, `bundle-notes.json`, `artifacts/`, `policy/test-policy.json`, `policy/audit.log`를 제외합니다.
- 검사 기준 커밋 직전의 변경분과 저장소 파일 전체에서 개인키 머리글, `sb_secret_` 값, `sk-` 긴 값, JWT 형태, 공개용 키 형태를 찾는 검사를 했고 결과는 "없음"입니다. 이 검사는 패턴을 찾는 것이라 모든 비밀값이 없다는 증명이 아닙니다.
- 이 저장소의 코드는 비밀값을 응답, 화면, 로그, 오류 메시지에 싣지 않도록 만들었고 시험이 그 점을 확인합니다. 기기 값은 `HttpOnly` 쿠키로만 다루고 DB에는 해시만 저장합니다.
- 코딩 도구와 이 문서는 비밀값을 요구하거나 다시 출력하지 않습니다. 값이 필요하면 학생이 공식 설정 화면에 직접 입력합니다.

### 재현 순서

새 폴더에서 처음부터 같은 결과를 얻는 순서입니다. 1~6번은 검사 기준 커밋 `1f2f702`로 실제 실행했습니다.

1. `git clone <저장소 주소> choi-bujang-vault`, `cd choi-bujang-vault`, `git checkout 1f2f702`. (확인: 커밋 `1f2f702`)
2. `node --version`으로 22 이상인지 보고 `npm install`. (확인: 오류 없이 끝남)
3. `node --test test/*.test.mjs`. (확인: 242개 중 242개 통과, 실패 0, 건너뜀 0)
4. `npm run decider:test`, `npm run fixture:7`, `npm run detect:test`. (확인: 판정기 4줄 `통과`, `정상 사건: allow`와 `복합 이상 사건: step_up`, 탐지 6줄 `통과`)
5. `npm run build -- --local`. (확인: 공개 자료 복사 메시지)
6. `npm run recheck`, 그리고 `npm run recheck -- --deployed <배포 주소>`. (확인: 로컬은 전체 72건 중 실측 50건 일치·불일치 0건·미실행 22건, 배포 주소 포함은 실측 62건 일치·불일치 0건·미실행 10건. 41종 공격은 목록이 없어 미실행입니다.)
7. **학생이 직접 (`미실행`):** DB 표 만들기, 환경 변수 입력, Vercel 연결과 배포, 첫 기기 승인(11단계 절), 로그인해 메모 읽기·추가·수정·삭제, 승인 전 기기에서 자료가 보이지 않는지 확인, 작전실 열기.
8. **제출 (`미실행`):** 변경을 커밋하고 푸시한 뒤 `bundle-notes.json`을 준비하고 `npm run bundle`을 실행합니다.
9. 문제가 생기면 위 "중지"와 "복구" 절을 따르고, 끝나면 `npm run recheck`로 다시 확인합니다.

### 이 안내의 한계

- 위 5번까지의 명령은 가짜 저장소와 가상 요청으로 하는 로컬 연습이며 심판 판정이 아닙니다. 41종 공격 방어 여부는 심판이 판정하고 이 저장소는 그 결과를 만들지 못합니다.
- 제공 엔진의 설치·실행·중지 방법은 이 저장소에 없어서 적지 않았습니다. 엔진이 요구하는 것은 `decide`와 `detect` 함수를 계약대로 제공하는 것까지만 확인했습니다.
- 이유 코드(`approved`, `device_not_registered`, `route_not_allowed`, `zone_forbidden`, `step_up_required`, `burst_read`)가 엔진의 등록부에 있는지는 확인하지 못했습니다.
- Vercel과 Supabase 화면 조작, 실제 계정 요청, 실제 브라우저 동작은 이 환경에서 실행하지 못했습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 비공개 설정값·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.



