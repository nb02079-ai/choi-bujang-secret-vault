// 시험 도우미: node --import 로 불러와 모듈 불러오기 추적을 켭니다.
import { register } from 'node:module';

register('./trace-hooks.mjs', import.meta.url);
