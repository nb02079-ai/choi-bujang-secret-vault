// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 지금은 device_registered 규칙 하나만 구현했습니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered']);

// 계약상 deviceId는 확인된 기기의 16자리 소문자 16진수 ID입니다.
const VERIFIED_DEVICE_ID = /^[0-9a-f]{16}$/u;

export async function decide(request) {
  // 6단계 device_registered: 엔진이 확인한 deviceRegistered가 true이고 확인된 deviceId가 함께 있을 때만 허용합니다.
  // false, 값 없음, 확인된 기기 ID가 없는 요청, 그 밖의 값은 모두 미등록으로 보고 거부합니다.
  const registered = request?.deviceRegistered === true
    && typeof request.deviceId === 'string' && VERIFIED_DEVICE_ID.test(request.deviceId);
  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: registered ? 'allow' : 'deny',
    reasonCode: registered ? 'approved' : 'device_not_registered',
    ruleIds: [RULE_IDS[0]],
  };
}
