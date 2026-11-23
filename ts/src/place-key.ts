/**
 * place-key — put an entry into the output object of a walker (SPEC 8, key collisions). Keys of
 * one object that redaction changes to the same key lose no value: the first keeps the key, each further one
 * gets a number inside its last placeholder, `[REDACTED:<rule>#2]`, `#3`, ... A key that redaction leaves
 * unchanged always keeps its own name: the input keys of the object that hold a placeholder are reserved up
 * front, so a generated number never takes the name of a key that is written in the input.
 */
import { lastPlaceholder } from './placeholder.js';
import { redactKey, type KeyDetector } from './redact-key.js';
import { setOwnKey } from './own-key.js';
import { ALGORITHMS_SPEC } from './spec.js';

const { open, close, numberMark } = ALGORITHMS_SPEC.placeholder;
const PLACEHOLDER_START = open.slice(0, open.indexOf(':'));
const FIRST_SUFFIX = 2;

/** Per output object: the reserved names and the last number given to each changed key. */
export type KeyPlacer = { reserved: ReadonlySet<string>; last: Map<string, number> };

export function newPlacer(reserved: ReadonlySet<string> = new Set()): KeyPlacer {
    return { reserved, last: new Map() };
}

/** The input keys that can be reserved: those that hold a placeholder. The caller scans them and reserves
 *  the ones its key scan leaves unchanged. */
export function keysHoldingPlaceholder(keys: readonly string[]): string[] {
    return keys.filter((key) => key.includes(PLACEHOLDER_START));
}

function endsWithNumber(rule: string): boolean {
    const at = rule.lastIndexOf(numberMark);
    if (at === -1 || at === rule.length - numberMark.length) return false;
    return [...rule.slice(at + numberMark.length)].every((char) => char >= '0' && char <= '9');
}

/** Where the number goes in a changed key: just before the `]` of its last placeholder, when that is
 *  `[REDACTED:<rule>]` with a rule that is not itself numbered (no `:suffix`). Otherwise undefined. */
function numberAt(key: string): number | undefined {
    const last = lastPlaceholder(key);
    if (last === undefined || !key.startsWith(open, last.start)) return undefined;
    const rule = key.slice(last.start + open.length, last.end - close.length);
    if (rule.includes(':') || endsWithNumber(rule)) return undefined;
    return last.end - close.length;
}

/** Store `value` under the key `outKey` (the key after redaction; `changed`: redaction changed it). */
export function placeKey(
    target: Record<string, unknown>,
    placer: KeyPlacer,
    outKey: string,
    changed: boolean,
    value: unknown,
): void {
    const isTaken = (name: string): boolean => placer.reserved.has(name) || Object.hasOwn(target, name);
    const at = changed && isTaken(outKey) ? numberAt(outKey) : undefined;
    if (at === undefined) {
        setOwnKey(target, outKey, value);
        return;
    }
    const named = (number: number): string =>
        `${outKey.slice(0, at)}${numberMark}${number}${outKey.slice(at)}`;
    let number = Math.max(placer.last.get(outKey) ?? 0, FIRST_SUFFIX - 1) + 1;
    while (isTaken(named(number))) number += 1;
    placer.last.set(outKey, number);
    setOwnKey(target, named(number), value);
}

/** For the keys of one stored object: output key -> the stored key it comes from, named as the walkers name
 *  them with the key scan `detect` (reserved names and numbers: the very placement of `placeKey`). */
export function redactedKeyNames(keys: readonly string[], detect: KeyDetector): Map<string, string> {
    const reserved = keysHoldingPlaceholder(keys).filter((key) => redactKey(key, [], detect) === key);
    const placer = newPlacer(new Set(reserved));
    const named: Record<string, unknown> = {};
    for (const key of keys) {
        const outKey = redactKey(key, [], detect);
        placeKey(named, placer, outKey, outKey !== key, key);
    }
    return new Map(Object.entries(named).map(([outKey, key]) => [outKey, key as string]));
}
