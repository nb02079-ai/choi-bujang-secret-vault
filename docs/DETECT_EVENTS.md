# 9단계 탐지 연습 사건 계약

`npm run detect:test`는 학생이 작성한 `src/detect.mjs`의 `detect(events)`에 가상 조회 사건을 전달합니다. 각 사건은 다음 세 값만 가집니다.

```js
{ at: '2026-10-01T00:00:00.000Z', method: 'GET', identity: { sub: 'learner_fixture' } }
```

같은 `identity.sub`의 `GET` 사건이 어느 10분 구간에서든 **120건을 넘을 때만** `{ action: 'propose_revocation', reasonCode: 'burst_read', subject: '해당 sub' }`를 돌려줍니다. 그 밖에는 `{ action: 'observe' }`입니다. 정확히 120건은 회수 제안 대상이 아닙니다. 다른 사용자의 사건을 합산하거나 10분 밖의 사건을 같은 묶음으로 세지 않습니다.

## 학생 구현의 추가 사항 (9단계)

이 저장소의 `src/detect.mjs`는 위 연습 계약보다 엄격합니다. 사건에 `deviceId`(16자리 소문자 16진수)와 `signals: { source: 'judge_fixture', network }`가 있을 때만 읽습니다. 같은 (주체, 기기) 쌍의 `GET`이 10분 구간에서 120건을 넘고 그 구간에 `network: 'unusual'`이 함께 있을 때만 `{ action: 'propose_revocation', reasonCode: 'burst_read', subject, device }`를 돌려줍니다. 그래서 위 연습 사건(`deviceId`와 네트워크 값 없음)의 121건·200건은 `observe`가 나오며 `npm run detect:test`에서 `확인 필요`로 남습니다. 결과의 `device` 항목은 연습 계약에 없는 확장입니다.

이 파일의 사건 모양은 **로컬 연습용**입니다. 브라우저가 보낸 사용자 번호를 신원으로 취급하지 않습니다. 운영 반 엔진이 검증한 사건을 전달하고 회수 제안을 집행하는 경로는 별도로 연결·시험해야 합니다. 이 명령의 통과를 실제 접속 차단이나 심판 판정으로 표시하지 않습니다.
