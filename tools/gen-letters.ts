#!/usr/bin/env bun
/**
 * gen-letters — generates the letter table of the spec (SPEC.md section 5.6): every code point of the
 * Unicode 15.0.0 General Categories Lu, Ll, Lt, Lm and Lo, as sorted hex ranges, written into
 * `spec/algorithms.json` as `letters.ranges` (`41-5a,61-7a,aa,b5,...`; a single code point is written
 * without a dash). The input is `UnicodeData.txt` of Unicode 15.0.0, downloaded from unicode.org and
 * checked against the SHA-256 below; only the generated table is committed.
 *
 *   bun tools/gen-letters.ts                 write the table
 *   bun tools/gen-letters.ts --check         fail when `spec/algorithms.json` differs from the table
 *   bun tools/gen-letters.ts --data FILE     read UnicodeData.txt from FILE instead of downloading it
 *   bun tools/gen-letters.ts --diff-node     list the code points where the table and the running Node
 *                                            (`\p{L}`, its own Unicode version) differ
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const ROOT = resolve(import.meta.dir, '..');
const ALGORITHMS = join(ROOT, 'spec', 'algorithms.json');
const UNICODE_VERSION = '15.0.0';
const DATA_URL = `https://www.unicode.org/Public/${UNICODE_VERSION}/ucd/UnicodeData.txt`;
const DATA_SHA256 = '806e9aed65037197f1ec85e12be6e8cd870fc5608b4de0fffd990f689f376a73';
const LETTER_CATEGORIES = new Set(['Lu', 'Ll', 'Lt', 'Lm', 'Lo']);
const MAX_CODE_POINT = 0x10ffff;
const RANGES_LINE = /^(\s*"ranges": ")[0-9a-f,-]*(",?)$/m;

export type Range = [number, number];

/** The letter ranges of a `UnicodeData.txt`, merged and sorted. */
export function letterRanges(unicodeData: string): Range[] {
    const ranges: Range[] = [];
    let rangeStart = -1;
    for (const line of unicodeData.split('\n')) {
        if (line === '') continue;
        const [hex, name, category] = line.split(';') as [string, string, string];
        const codePoint = Number.parseInt(hex, 16);
        if (name.endsWith(', First>')) {
            rangeStart = codePoint;
            continue;
        }
        const first = name.endsWith(', Last>') ? rangeStart : codePoint;
        if (LETTER_CATEGORIES.has(category)) ranges.push([first, codePoint]);
    }
    return merge(ranges);
}

function merge(ranges: Range[]): Range[] {
    const merged: Range[] = [];
    for (const [low, high] of [...ranges].sort((a, b) => a[0] - b[0])) {
        const last = merged[merged.length - 1];
        if (last !== undefined && low <= last[1] + 1) last[1] = Math.max(last[1], high);
        else merged.push([low, high]);
    }
    return merged;
}

export function encodeRanges(ranges: Range[]): string {
    return ranges
        .map(([low, high]) => (low === high ? low.toString(16) : `${low.toString(16)}-${high.toString(16)}`))
        .join(',');
}

export function decodeRanges(encoded: string): Range[] {
    return encoded.split(',').map((item) => {
        const [low, high] = item.split('-').map((part) => Number.parseInt(part, 16)) as [number, number?];
        return [low, high ?? low];
    });
}

async function readUnicodeData(path: string | undefined): Promise<string> {
    const bytes =
        path === undefined ? Buffer.from(await (await fetch(DATA_URL)).arrayBuffer()) : readFileSync(path);
    const digest = createHash('sha256').update(bytes).digest('hex');
    if (digest !== DATA_SHA256) throw new Error(`UnicodeData.txt ${UNICODE_VERSION}: unexpected SHA-256`);
    return bytes.toString('utf8');
}

/** Code points where the table and the `\p{L}` of the running Node disagree. */
export function nodeDifferences(ranges: Range[]): number[] {
    const letters = /^\p{L}$/u;
    const inTable = new Uint8Array(MAX_CODE_POINT + 1);
    for (const [low, high] of ranges) inTable.fill(1, low, high + 1);
    const differing: number[] = [];
    for (let codePoint = 0; codePoint <= MAX_CODE_POINT; codePoint++) {
        const isSurrogate = codePoint >= 0xd800 && codePoint <= 0xdfff;
        const nodeSays = !isSurrogate && letters.test(String.fromCodePoint(codePoint));
        if (nodeSays !== (inTable[codePoint] === 1)) differing.push(codePoint);
    }
    return differing;
}

function tableInFile(): string {
    const match = /^\s*"ranges": "([0-9a-f,-]*)"/m.exec(readFileSync(ALGORITHMS, 'utf8'));
    if (match === null) throw new Error('spec/algorithms.json holds no letters.ranges line');
    return match[1] as string;
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const dataIndex = args.indexOf('--data');
    const table = encodeRanges(
        letterRanges(await readUnicodeData(dataIndex === -1 ? undefined : args[dataIndex + 1])),
    );
    if (args.includes('--diff-node')) {
        const differing = nodeDifferences(decodeRanges(table));
        console.log(`${differing.length} code points differ (Node ${process.versions.unicode}):`);
        console.log(differing.map((codePoint) => codePoint.toString(16)).join(','));
        return;
    }
    if (args.includes('--check')) {
        if (tableInFile() !== table) {
            console.error(
                'spec/algorithms.json letters.ranges is not the Unicode 15.0.0 table; run tools/gen-letters',
            );
            process.exit(1);
        }
        console.log('letters.ranges is the Unicode 15.0.0 table');
        return;
    }
    const text = readFileSync(ALGORITHMS, 'utf8');
    writeFileSync(ALGORITHMS, text.replace(RANGES_LINE, `$1${table}$2`));
    console.log(`wrote ${table.split(',').length} ranges`);
}

if (import.meta.main) await main();
