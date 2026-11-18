/** Attack units for the scaling test: each is repeated to 100 KB and 1 MB and run through every pattern. */
import type { SpecDir } from './spec-patterns.ts';

export type Attack = { name: string; unit: string };

const FIXED_UNITS = [
    'a-',
    'a_',
    'A-',
    '-',
    '_',
    ' ',
    '\t',
    '\u00a0',
    '\n',
    ' a',
    'a ',
    ':',
    '=',
    ': ',
    '= ',
    '"',
    "'",
    '\\',
    '\\"',
    "\\'",
    '\\\\"',
    '?a=',
    '&a=',
    '?token=',
    '&token=',
    '%41',
    '%3Ftoken%3D',
    '%3F',
    '://',
    'a://u:',
    'a://',
    '-----BEGIN PRIVATE KEY-----',
    '-----BEGIN PRIVATE KEY-----!',
    '-----BEGIN PRIVATE KEY-----#',
    '?password=Ab1defgh ',
    '?password=Abc12345 ',
    '-----BEGIN ',
    '-----END ',
    'eyJ-',
    'eyJ.',
    'eyJabcdefghijk.',
    'Bearer ',
    'Basic AAAAAAAA ',
    'Token AAAAAAAA ',
    'xai-',
    'AIza',
    'ghp_',
    'github_pat_',
    'sk-',
    'sk-ant-',
    'srt1.',
    'srt2.',
    'dr_sk_',
    'xoxb-',
    'AKIA',
    'Cookie:',
    'Set-Cookie:',
    'a=b; ',
    '[REDACTED',
    '[REDACTED:',
    ']',
    'password="',
    "password='",
    'password=\\"',
    '{"password":"',
    '{\\"password\\":\\"',
];

function wordUnits(spec: SpecDir): string[] {
    const keys = spec.keys as { secretWords: string[][]; extraSequences: string[][] };
    const macros = spec.rules.macros;
    const keywordMacro = macros.KEYWORDS;
    const keywordWords = typeof keywordMacro === 'object' ? (keywordMacro.words ?? []) : [];
    const words = [...keys.secretWords, ...keys.extraSequences, ...keywordWords].map((parts) =>
        parts.join('_'),
    );
    return words.flatMap((word) => [`${word}=`, `${word}:`, `${word}_`, `${word}"=`, `${word} : "`]);
}

export function attacksFor(spec: SpecDir): Attack[] {
    const units = [...new Set([...FIXED_UNITS, ...wordUnits(spec)])];
    return units.map((unit) => ({ name: JSON.stringify(unit), unit }));
}
