// GET /api/ops/summary : 탈환 작전실 요약 (읽기 전용, 로그인과 기기 승인 필요)
import { opsApi } from '../../src/ops-api.mjs';

export default opsApi.summary;
