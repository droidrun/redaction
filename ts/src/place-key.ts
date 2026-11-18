/**
 * place-key — put an entry into the output object of a walker (SPEC 8, key collisions). Two different keys
 * of one object that redact to the same placeholder key lose no value: the first keeps the plain placeholder
 * key, each further one gets a number inside the brackets, `[REDACTED:<rule>#2]`, `#3`, ... (L-P).
 */
import { setOwnKey } from './own-key.js';
import { PLACEHOLDER_RE } from './placeholder.js';
import { ALGORITHMS_SPEC } from './spec.js';

const { open, close } = ALGORITHMS_SPEC.placeholder;
const FIRST_SUFFIX = 2;

/** Per output object: the last number given to each placeholder key (1 = the plain key itself). */
export type KeySlots = Map<string, number>;

/** `[REDACTED:<rule>]` exactly: a whole placeholder with a rule, no `:suffix`. The rule, or undefined. */
function ruleOfKey(key: string): string | undefined {
    if (!key.startsWith(open) || !PLACEHOLDER_RE.test(key)) return undefined;
    const rule = key.slice(open.length, key.length - close.length);
    return rule.includes(':') ? undefined : rule;
}

export function placeKey(
    target: Record<string, unknown>,
    slots: KeySlots,
    key: string,
    value: unknown,
): void {
    const rule = ruleOfKey(key);
    if (rule === undefined || !Object.hasOwn(target, key)) {
        if (rule !== undefined) slots.set(key, 1);
        setOwnKey(target, key, value);
        return;
    }
    let number = (slots.get(key) ?? 1) + 1;
    while (Object.hasOwn(target, `${open}${rule}#${number}${close}`)) number += 1;
    slots.set(key, number);
    setOwnKey(target, `${open}${rule}#${number}${close}`, value);
}
