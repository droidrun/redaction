/**
 * auth-values — `Bearer <value>`, and `Basic`/`Token <value>`. Basic and Token are
 * ordinary words, so their value must look like a credential: a run of the value
 * class of at least `minValueLength` that is not a plain lower-case word and not a
 * Capitalized word ("Token expired", "Basic information" stay). A word shape counts
 * when the run of letters is followed by a non-word character or the end.
 */
import { charTest, compile, type CharTest, type Range } from '../portable.js';
import { isPlaceholderValue } from './placeholder-value.js';
import type { Scanner } from './regex-rule.js';
import type { Rule } from '../spec.js';

type AuthRule = Rule & {
    bearer: string;
    scheme: string;
    valueClass: string;
    minValueLength: number;
    lowerClass: string;
    upperClass: string;
    wordClass: string;
    plainWords: string[];
};

function runEnd(text: string, from: number, test: CharTest): number {
    let end = from;
    while (end < text.length && test(text[end] as string)) end += 1;
    return end;
}

function prepareBearer(rule: AuthRule): Scanner {
    const pattern = compile(rule.bearer, 'gd');
    return (text) => {
        const ranges: Range[] = [];
        for (const match of text.matchAll(pattern)) {
            const range = match.indices?.[1];
            if (range) ranges.push([range[0], range[1]]);
        }
        return ranges;
    };
}

function prepareScheme(rule: AuthRule): Scanner {
    const [isValue, isLower, isUpper, isWord] = [
        rule.valueClass,
        rule.lowerClass,
        rule.upperClass,
        rule.wordClass,
    ].map(charTest) as [CharTest, CharTest, CharTest, CharTest];
    const pattern = compile(rule.scheme, 'g');
    return (text) => {
        const endsWord = (at: number): boolean => at >= text.length || !isWord(text[at] as string);
        const ranges: Range[] = [];
        pattern.lastIndex = 0;
        for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
            const start = match.index + match[0].length;
            const end = runEnd(text, start, isValue);
            const lowerEnd = runEnd(text, start, isLower);
            const capitalizedEnd = isUpper(text[start] ?? '') ? runEnd(text, start + 1, isLower) : start;
            const isPlainWord = lowerEnd > start && endsWord(lowerEnd);
            const isCapitalized = capitalizedEnd > start + 1 && endsWord(capitalizedEnd);
            if (end - start < rule.minValueLength || isPlainWord || isCapitalized) {
                pattern.lastIndex = match.index + 1;
                continue;
            }
            ranges.push([start, end]);
            pattern.lastIndex = end;
        }
        return ranges;
    };
}

export function prepareAuthValues(rule: AuthRule): Scanner {
    const plainWords = new Set(rule.plainWords);
    const bearer = prepareBearer(rule);
    const scheme = prepareScheme(rule);
    return (text) => {
        return [...bearer(text), ...scheme(text)].filter(([start, end]) => {
            const word = text.slice(start, end).toLowerCase();
            return !plainWords.has(word) && !isPlaceholderValue(text, start, end);
        });
    };
}
