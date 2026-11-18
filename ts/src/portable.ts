/**
 * portable.ts — compiles spec patterns. A spec pattern is written in the portable
 * grammar, so the only flags the interpreter may add are the scanning ones.
 */
import { expandPattern } from './spec.js';

export type Range = [number, number];
export type CharTest = (unit: string) => boolean;

const SCAN_FLAGS = /^[gyd]*$/;

export function compile(template: string, flags = ''): RegExp {
    if (!SCAN_FLAGS.test(flags)) throw new Error('spec patterns take scanning flags only');
    return new RegExp(expandPattern(template), flags);
}

/** A test for one UTF-16 code unit against a single-class spec pattern (`[A-Za-z]`). */
export function charTest(classPattern: string): CharTest {
    const re = new RegExp(`^${expandPattern(classPattern)}$`);
    return (unit) => re.test(unit);
}

/** A test for "the class matches somewhere in the string". */
export function containsTest(classPattern: string): (text: string) => boolean {
    const re = new RegExp(expandPattern(classPattern));
    return (text) => re.test(text);
}

/** ASCII fold used for every case-insensitive comparison of the spec: A-Z to a-z and
 *  U+212A (KELVIN SIGN, lower-cases to `k`); every other character is left as it is. */
export function foldLower(text: string): string {
    return text.replace(/[A-ZK]/g, (char) => (char === 'K' ? 'k' : char.toLowerCase()));
}
