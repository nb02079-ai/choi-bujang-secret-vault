// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 지금은 device_registered 규칙 하나만 구현했습니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered']);

export async function decide(request) {
  // 6단계 device_registered: 엔진이 확인한 deviceRegistered가 true일 때만 허용합니다.
  // false, 값 없음, 그 밖의 값은 모두 미등록으로 보고 거부합니다.
  const registered = request?.deviceRegistered === true;
  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: registered ? 'allow' : 'deny',
    reasonCode: registered ? 'approved' : 'device_not_registered',
    ruleIds: [RULE_IDS[0]],
  };
}
