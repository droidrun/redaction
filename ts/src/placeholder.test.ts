/**
 * placeholder.test.ts — one grammar: what `buildPlaceholder`/`buildReadPlaceholder`
 * emit is exactly what PLACEHOLDER_RE accepts, and a value counts as a placeholder
 * only when it is entirely one.
 */
import { expect, test } from 'bun:test';
import {
    buildPlaceholder,
    buildReadPlaceholder,
    literalSegments,
    PLACEHOLDER_ANYWHERE_RE,
    PLACEHOLDER_RE,
    placeholderEndAt,
} from './placeholder.js';

const MATCHED = [
    'aaaaaaaaaaaaaaaaaaaa', `${'a'.repeat(16)}a b `, `${'a'.repeat(16)}x]y[`, `${'a'.repeat(16)}\n\t:  `,
    `${'a'.repeat(16)}]]]]`, 'short',
];

test.each(MATCHED)('buildPlaceholder output is accepted by PLACEHOLDER_RE: %j', (matched) => {
    const placeholder = buildPlaceholder('@secretlint/secretlint-rule-aws', matched);
    expect(PLACEHOLDER_RE.test(placeholder)).toBe(true);
    expect(placeholderEndAt(placeholder, 0)).toBe(placeholder.length);
    expect(literalSegments(placeholder)).toEqual(['', '']);
});

test('read placeholder and the legacy forms are placeholders', () => {
    for (const text of [buildReadPlaceholder('jwt'), '[REDACTED]', '[REDACTED:a:b]', '[REDACTED:a:a b]']) {
        expect(PLACEHOLDER_RE.test(text)).toBe(true);
    }
});

test('a value is a placeholder only when it is entirely one', () => {
    const texts = [
        'x [REDACTED]', '[REDACTED] x', '[REDACTED][REDACTED]', '[REDACTED:a] tail', '[REDACTED:a b]',
    ];
    for (const text of texts) {
        expect(PLACEHOLDER_RE.test(text)).toBe(false);
    }
    expect(PLACEHOLDER_ANYWHERE_RE.test('x [REDACTED:a] y')).toBe(true);
});

test('brackets in the last four characters cannot end the placeholder early', () => {
    expect(buildPlaceholder('aws', `${'a'.repeat(16)}]x[y`)).toBe('[REDACTED:aws:*x*y]');
});

test('literalSegments splits around every placeholder', () => {
    expect(literalSegments('a [REDACTED] b [REDACTED:x:ab cd] c')).toEqual(['a ', ' b ', ' c']);
});
