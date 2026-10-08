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
- 화면 `/`에 Supabase Auth 이메일·비밀번호 로그인·로그아웃이 있습니다. 공식 `@supabase/supabase-js`를 쓰고, 화면 코드에는 공개용 Project URL과 publishable key만 있었습니다(5단계에서 화면 밖으로 옮겼습니다. 아래 5단계 참고). 로그인 실패 이유는 화면에 표시합니다.
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

3단계 당시의 한계(정상 로그인 뒤 추가·수정·삭제를 코드로 실행하지 않은 것, 소유자 검사가 없어 B가 A의 메모 `id`로 접근할 수 있었던 것)는 4단계에서 소유자 검사로 막았습니다. 아래 4단계를 보세요.

## 4단계: 로그인해도 내 자료만 보이게 합니다

**현재 작동하는 기능 (4단계 저장점):**
- 서버(`src/notes-api.mjs`)는 검증된 사용자 ID와 DB 행의 `owner_id`를 코드에서 직접 비교합니다. 읽기(목록·한 건)·추가·수정·삭제를 모두 본인 메모로 제한하고, 허용되지 않은 요청은 기본 거부합니다.
- 목록은 본인 메모만 돌려줍니다. 한 건 조회·수정·삭제에서 남의 메모, 주인이 없는 메모, 없는 메모는 모두 같은 404입니다. 존재 여부를 알려 주지 않기 위해서입니다.
- 추가할 때 `owner_id`는 검증된 사용자 ID로만 저장합니다. URL·본문의 `owner_id`는 믿지 않습니다.
- 수정은 기존 행이 본인 것이어야 하고 새 행의 소유자도 본인이어야 합니다. 본문이 다른 `owner_id`(다른 사람·null·숫자·빈 값)를 내세우면 쓰기 전에 403으로 거부합니다. 저장소에 보내는 수정·삭제에도 `owner_id=본인` 조건을 다시 겁니다.
- 한 건 응답은 `{id,title,body}`, 수정 본문은 `{title,body}`입니다. `allowedRoutes` 5개는 실제 처리하는 방식·경로와 정확히 같고, 시험이 이를 확인합니다.
- DB 쪽: 로컬 `supabase/003_rls_least_privilege.sql`(Git에 올리지 않음)이 `vault_notes`의 기존 권한을 `REVOKE ALL … FROM PUBLIC, anon, authenticated`로 회수하고 `authenticated`에 `SELECT·INSERT·UPDATE·DELETE`만 줍니다. RLS 정책은 `SELECT`·`DELETE`는 기존 행(USING), `INSERT`는 새 행(WITH CHECK), `UPDATE`는 둘 다 `auth.uid() = owner_id`일 때만 허용합니다. 앱 서버는 RLS를 우회하는 서버 비밀키로 접속하므로, 서버 코드의 소유자 비교가 1차 방어이고 GRANT·RLS는 키 없이 DB에 직접 닿는 경로를 막는 2차 방어입니다.
- 기존 가상 메모의 소유자 연결은 로컬 `supabase/002_assign_owners.sql`로 했습니다. `과제`·`포트폴리오`·`아침 리추얼`은 A, `B의 시험 메모`는 B 소유이고, `훈련 행정 자료`는 주인이 없어 누구도 접근하지 못합니다.

**다시 실행하는 방법:**
1. Supabase 대시보드의 Authentication → Users → Add user에서 가상 A·B 계정을 만들고 Auto Confirm User를 체크합니다. 실제 이메일은 쓰지 않고 비밀번호는 학생이 직접 정합니다.
2. SQL Editor에서 `002_assign_owners.sql`의 자리표시자를 두 계정 이메일로 바꿔 실행하고, 그다음 `003_rls_least_privilege.sql`을 `[1]` 적용 전 점검 → `[2]` 적용 → `[3]` 적용 후 점검 순서로 따로 실행합니다. 두 SQL은 Git에 없으므로 필요하면 코딩 도구에 다시 만들게 합니다.
3. 배포 주소에서 A로 로그인해 자기 메모를 읽고 추가·수정·삭제하고, B로도 같게 해 봅니다. 각자 목록에는 자기 메모만 보여야 합니다.
4. 로컬 시험은 `npm run test:r5`입니다. 가짜 검사기와 메모리 저장소를 쓰므로 실제 Supabase 동작을 증명하지 않습니다.

**학생이 SQL Editor에서 실행해 보고한 적용 후 점검 결과:** `role_table_grants`는 `authenticated`만 `DELETE, INSERT, SELECT, UPDATE`이고 PUBLIC·anon 행이 없습니다. `has_table_privilege`는 `anon`이 없음, `authenticated`가 `SELECT, INSERT, UPDATE, DELETE`뿐이고, `service_role`은 앱 API가 쓰는 권한을 유지합니다. `anon`에는 컬럼 단위 권한도 없습니다. RLS는 켜져 있고 정책은 네 개이며 모두 `roles={authenticated}`, 조건은 `auth.uid() = owner_id`입니다. 이 값은 학생이 붙여 준 결과이고, 코딩 도구는 DB에 접속하지 않았습니다.

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
- 서버가 RLS를 우회하는 비밀키로 접속하므로, 서버 코드의 소유자 비교에 버그가 있으면 DB의 RLS가 막아 주지 못합니다. 비밀키가 유출되면 모든 메모가 노출됩니다.
- 추가할 때 이미 있는 `id`를 보내면 409가 돌아와, 그 `id`가 어딘가에 있다는 것을 알려 줍니다. UUID라 추측은 어렵지만 작은 신호입니다.
- 주인이 없는 `훈련 행정 자료`는 누구도 읽거나 고칠 수 없는 채로 DB에 남아 있습니다.
- 공개 anon 키는 화면 코드에 있고 권한이 없어 거부되지만, 키가 공개되어 있다는 사실은 그대로입니다.
- `/aleph.json`에는 1단계 시작 틀 확인 표시(`sampleMarker`)가 남아 있습니다. 배포 신원 파일이 설정값을 그대로 적기 때문입니다.
- 2단계에서 적은 과거 노출은 해소되지 않았습니다. 옛 공개 커밋, `origin/main`, 태그 `r5-rc1`에 옛 가상 메모가 남아 있습니다.

## 5단계: 자료 요청을 서버 한곳으로 모읍니다

**현재 작동하는 기능 (5단계 저장점):**
- 브라우저 코드(`public/index.html`)는 Supabase를 직접 부르지 않습니다. `supabase-js`와 Project URL, 공개(publishable) 키를 화면에서 모두 없앴습니다. 로그인·토큰 갱신·로그아웃은 서버 함수 `POST /api/auth/login`, `/api/auth/refresh`, `/api/auth/logout`(`src/auth-api.mjs`)이 Supabase Auth로 대신 전달하고, 메모 읽기·추가·수정·삭제는 `callApi()`로 `/api/notes`, `/api/notes/:id`만 부릅니다. 로그인 토큰은 그 탭의 `sessionStorage`에만 두고 탭을 닫으면 사라집니다. 서버 함수는 이메일·비밀번호·토큰을 로그에 남기지 않고, 로그인 실패는 계정 존재 여부를 알리지 않는 같은 문구로 답합니다.
- 로그인 서버 함수는 Vercel 환경변수 `SUPABASE_PUBLISHABLE_KEY`(공개용 키)를 서버에서만 읽습니다. 값은 학생이 Settings → Environment Variables에 직접 넣고, 넣은 뒤 Redeploy해야 합니다. 이 값이 없으면 로그인이 500(서버 설정 미완료)으로 실패합니다. `/api/auth/*`는 자료 API가 아니라서 `allowedRoutes`에 넣지 않았습니다.
- 서버 함수의 로그인 검사, 소유자 비교, 서버 전용 설정(`SUPABASE_URL`, `SUPABASE_SECRET_KEY`)은 4단계 그대로입니다. `allowedRoutes` 5개도 그대로입니다.
- `aleph.config.json`의 `originalApiUrl`은 쿼리 없는 원본 자료 주소 `https://hcaygyndhpfqrwlfbpqt.supabase.co/rest/v1/vault_notes`입니다. 이 주소를 공개 anon 키로 직접 부르면 거부되어야 하고, 메모가 보이면 안 됩니다. 배포 신원 파일 `/aleph.json`에도 같은 주소가 `originalApiUrl`로 실립니다(5단계부터, 쿼리가 없는 `https://` 경로가 아니면 빌드가 실패합니다). 허용 경로 목록 `allowedRoutes`(`GET /api/notes` 같은 형식, 1개 이상)도 `/aleph.json`에 실리며, 비어 있거나 형식이 다르면 빌드가 실패합니다. `restoreRoute`는 아직 `null`입니다.
- DB 쪽: 로컬 `supabase/004_revoke_direct_access.sql`(Git에 올리지 않음)이 `vault_notes`의 `PUBLIC`·`anon`·`authenticated` 권한을 모두 회수하고, `service_role`의 네 권한과 RLS가 남았는지 같은 트랜잭션에서 확인합니다. 003의 RLS 정책 네 개는 지우지 않고 2차 방어로 남깁니다.

**다시 실행하는 방법:**
0. Vercel 프로젝트의 Settings → Environment Variables에 `SUPABASE_PUBLISHABLE_KEY`(Supabase 대시보드의 공개 키)를 직접 넣고 Redeploy합니다. 코드·Git·채팅에는 적지 않습니다.
1. SQL Editor에서 `004_revoke_direct_access.sql`을 `[1]` 적용 전 점검 → `[2]` 적용 → `[3]` 적용 후 점검 순서로 따로 실행합니다. 이 SQL은 Git에 없으므로 필요하면 코딩 도구에 다시 만들게 합니다.
2. 배포 주소에서 A로 로그인해 메모를 읽고 추가·수정·삭제하고, B로도 해 봅니다. 각자 목록에는 자기 메모만 보여야 합니다.
3. 로컬 시험은 `npm run test:r5`, 자기 점검과 제출 묶음은 `npm run bundle`입니다.

**기록 범위:**
- `npm run bundle`의 `src/attack-check.mjs`는 첫 화면에 공개 키 형태의 문자열이 없는지 읽어 보고(`page_no_public_key`), 공개 키가 화면에 없으므로 anon 직접 요청에는 터미널 환경변수 `SUPABASE_PUBLISHABLE_KEY`의 값을 씁니다(결과·로그에 싣지 않습니다). 환경변수가 없으면 그 요청들은 미실행으로 남습니다. 보낸 요청의 결과는 `artifacts/submission.json`에만 남고 이 README에는 적지 않습니다(심판의 판정이 아닙니다). 5단계에서는 토큰 없는 요청, 공개 anon 키로 원본 주소에 직접 보낸 4가지 요청, 원본 주소에서 메모가 보이는지 읽어 보는 요청을 보냅니다.
- 미실행: 로그인 토큰을 실은 원본 주소 직접 요청(`authenticated_direct_rejected`), 정상 A 로그인 뒤 서버 함수 동작(`logged_in_own_crud`), B의 거부(`cross_user_access`). 계정 정보와 토큰을 코드에 넣지 않기 위해서이며 학생이 브라우저에서 직접 확인해야 합니다.
- **학생이 SQL Editor에서 실행해 보고한 004 적용 후 점검 결과:** `role_table_grants`에 `PUBLIC`·`anon`·`authenticated` 행이 없습니다. `has_table_privilege`는 `anon`과 `authenticated`가 모두 `(없음)`이고 `service_role`은 `SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER`를 유지합니다. `has_any_column_privilege`는 `anon`과 `authenticated` 모두 `(없음)`입니다. RLS는 켜져 있고(`true`) 정책은 4개(`policy_count`)입니다. 이 값은 학생이 붙여 준 결과이고, 코딩 도구는 DB에 접속하지 않았습니다. 적용 전 `[1]` 결과는 받지 않아 대조하지 못했습니다.
- 004 적용 뒤 `authenticated` 토큰으로 원본 주소를 직접 불러 거부되는지는 코드로 실행하지 않았습니다(`authenticated_direct_rejected`는 미실행).

**남아 있는 약점:** 서버가 RLS를 우회하는 비밀키로 접속하므로 서버의 소유자 비교가 유일한 1차 방어이고, 2단계의 과거 노출은 해소되지 않았습니다. 화면에서 공개 키는 없앴지만 로그인 토큰(access·refresh)은 `sessionStorage`에 있어 화면에 스크립트가 주입되면 읽힐 수 있습니다. 로그인 요청에 시도 횟수 제한이 없고(Supabase Auth 쪽 제한에 의존), 옛 커밋 기록에는 공개 키가 남아 있습니다. 로그인 서버 함수와 새 화면 코드는 가짜 fetch 시험과 문법 검사만 했고, 실제 Supabase로 로그인해 본 것이 아닙니다.

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
- `src/decider.mjs`는 시작 틀 그대로이고 `RULE_IDS`에 `xdr.bruteforce.deny`를 넣지 않았습니다. 거부 규칙은 메모리에만 있어 프로세스가 끝나면 사라집니다.
- `bf-11`, `bf-12`, `bf-17`처럼 실패 뒤 성공한 경보는 애매한 사례로 `alert`에 뒀습니다. 로컬 시험과 연습 실행이며 심판 판정이나 실제 접속 차단이 아닙니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
