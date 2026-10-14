// POST /api/notes/:id/restore : 비공개 사본에서 본인의 메모 한 건만 되살립니다.
import { notesApi } from '../../../src/notes-api.mjs';

export default notesApi.restore;
