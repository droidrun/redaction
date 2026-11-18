/**
 * protocol.test.ts — the comparison of the differential driver must see what it is there to see: key order,
 * lone surrogates, numbers at double level, rule-id counts, and lines that hold U+2028.
 */
import { expect, test } from 'bun:test';
import { canonicalJson, countKey, lines, toLine } from './protocol.ts';

test('key order counts, even for integer-like keys that JSON.parse would sort', () => {
    expect(canonicalJson('{"b":1,"1":2}')).not.toBe(canonicalJson('{"1":2,"b":1}'));
    expect(canonicalJson('{"b":1,"a":[]}')).toBe('{"b":1,"a":[]}');
});

test('a lone surrogate is not the replacement character, and an escaped pair is the astral character', () => {
    expect(canonicalJson('"\\ud800"')).not.toBe(canonicalJson('"\\ufffd"'));
    expect(canonicalJson('"\\ud83d\\ude00"')).toBe(canonicalJson(`"${'\u{1f600}'}"`));
});

test('numbers are compared as doubles, text as written does not count', () => {
    expect(canonicalJson('[1.0,1e2,9007199254740993]')).toBe(canonicalJson('[1,100,9007199254740992]'));
    expect(canonicalJson('[1]')).not.toBe(canonicalJson('[2]'));
    expect(canonicalJson('[-0]')).not.toBe(canonicalJson('[0]'));
});

test('strings, nesting and literals survive; trailing text is refused', () => {
    expect(canonicalJson(' {"a":[true,false,null,{"b":"x\\n"}]} ')).toBe(
        '{"a":[true,false,null,{"b":"x\\n"}]}',
    );
    expect(() => canonicalJson('{} x')).toThrow();
});

test('hit counts are compared by rule id, not by order or by listing', () => {
    expect(
        countKey([
            ['b', 1],
            ['a', 2],
        ]),
    ).toBe(
        countKey([
            ['a', 1],
            ['b', 1],
            ['a', 1],
        ]),
    );
    expect(countKey([['a', 1]])).not.toBe(countKey([['a', 2]]));
});

test('a line with U+2028 and U+2029 stays one line through toLine and lines', async () => {
    const text = 'a b c';
    const line = toLine({ text });
    expect(line.includes(' ') || line.includes(' ')).toBe(false);
    expect(JSON.parse(line)).toEqual({ text });
    async function* chunks(): AsyncGenerator<string> {
        yield `${line}\nsecond`;
        yield ' half\n';
    }
    const out: string[] = [];
    for await (const item of lines(chunks())) out.push(item);
    expect(out).toEqual([line, 'second half']);
});
