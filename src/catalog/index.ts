import type { Rule } from '../types.js';
import { class1Rules } from './class1.js';
import { class2Rules } from './class2.js';

export { class1Rules } from './class1.js';
export { class2Rules } from './class2.js';

export function loadCatalog(): readonly Rule[] {
  return [...class1Rules, ...class2Rules];
}
