/**
 * credential-uri — URLs with `user:password@` that look real (SPEC 4.15): one portable pattern whose
 * capture groups 1 and 2 are the user and the password, then the checks of the upstream rules (too short,
 * a stand-in word, a template such as `${PASSWORD}`, one repeated character). A match that fails a check
 * is consumed and not reported, like the expression it replaces.
 */
import { compile, foldLower, type Range } from '../portable.js';
import type { Rule } from '../spec.js';
import type { Scanner } from './regex-rule.js';

type CredentialRule = Rule & {
    pattern: string;
    userMin?: number;
    passwordMin: number;
    userIgnoreContains?: string[];
    passwordIgnoreContains?: string[];
    passwordIgnoreEquals?: string[];
    userEqualsPassword?: boolean;
    variablePatterns?: string[];
    repeatRun: number;
};

function containsAny(value: string, items: string[] | undefined): boolean {
    const folded = foldLower(value);
    return (items ?? []).some((item) => folded.includes(foldLower(item)));
}

function equalsAny(value: string, items: string[] | undefined): boolean {
    const folded = foldLower(value);
    return (items ?? []).some((item) => folded === foldLower(item));
}

/** At least `runLength` units, all the same unit. */
function isRepeated(value: string, runLength: number): boolean {
    if (value.length < runLength) return false;
    for (let at = 1; at < value.length; at++) {
        if (value[at] !== value[0]) return false;
    }
    return true;
}

export function prepareCredentialUri(rule: CredentialRule): Scanner {
    const pattern = compile(rule.pattern, 'g');
    const variables = (rule.variablePatterns ?? []).map((source) => compile(source));
    const isRealUser = (user: string): boolean => {
        return user.length >= (rule.userMin ?? 0) && !containsAny(user, rule.userIgnoreContains);
    };
    const isRealPassword = (user: string, password: string): boolean => {
        if (rule.userEqualsPassword === true && user === password) return false;
        if (password.length < rule.passwordMin) return false;
        if (variables.some((variable) => variable.test(password))) return false;
        if (containsAny(password, rule.passwordIgnoreContains)) return false;
        if (equalsAny(password, rule.passwordIgnoreEquals)) return false;
        return !isRepeated(password, rule.repeatRun);
    };
    return (text) => {
        const ranges: Range[] = [];
        for (const match of text.matchAll(pattern)) {
            const [whole, user, password] = match;
            if (!user || !password) continue;
            if (!isRealUser(user) || !isRealPassword(user, password)) continue;
            const start = match.index as number;
            ranges.push([start, start + whole.length]);
        }
        return ranges;
    };
}
