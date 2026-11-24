/** Attack units for the scaling test: each is repeated to 100 KB and 1 MB and run through every pattern. A
 *  composite attack (`head`) starts with a short cluster and then repeats the unit: a long run behind many starts. */
import type { SpecDir } from './spec-patterns.ts';

/** `texts` (by size, as a string key) are ready-made texts that replace the head-and-unit text: the attack string
 *  of a recheck verdict, built at each size by `recheck-gate.ts`. */
export type Attack = { name: string; unit: string; head?: string; texts?: Record<string, string> };

/** The text of an attack at `size` units: the head, then the unit repeated up to `size`. */
export function attackText(attack: Attack, size: number): string {
    const exact = attack.texts?.[String(size)];
    if (exact !== undefined) return exact;
    const head = attack.head ?? '';
    return (
        head +
        attack.unit.repeat(Math.ceil(size / attack.unit.length)).slice(0, Math.max(0, size - head.length))
    );
}

/** Starts of the cluster of a composite attack; each is within reach of the long run behind it. */
const CLUSTER_STARTS = 170;

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
    // The strict pairs and the `pii` group (SPEC 4.6a, 4.18 to 4.21): near misses of every pattern.
    'token=',
    'token: ',
    'a=a=',
    'password => "',
    'a@',
    'a@a.',
    'a.a@a.a',
    'a@a.a.',
    '+1',
    '+1 2',
    '1 ',
    '1.',
    '255.',
    '1.1.1.',
    '1:',
    'a:',
    '::',
    '[1:',
    '[a::',
    '415-555-',
    '(415) ',
    '0123 ',
    'code ',
    'OTP code ',
    'code is 1',
    'code 1',
    'version ',
    'error code ',
    // The full tier (SPEC 4.11 to 4.15): every algorithm gets its prefixes, its separators and the
    // repeated near-miss shapes that make a restart loop slow.
    'ghs_1_',
    'ghs_1_a.',
    'ghs_1_a.a.',
    'SG.',
    'SG.a.',
    'SG.a.a-',
    'SG.a.a_',
    'SG.a.aSG.a.',
    'xoxb-',
    'xoxb-a-',
    'xoxb-a_',
    'xoxb-1-a-',
    'xoxb-a--',
    'ops_ey',
    'ops_eyfQ=',
    'sk-ant-api03-',
    'sk-ant-api03-AA',
    'glc_',
    'glc_A=',
    'tskey-a-',
    'tskey-auth-a-',
    'dapi',
    'dapi-1',
    '-----BEGIN RSA PRIVATE KEY-----\n',
    '-----BEGIN PRIVATE KEY-----\nMI',
    '-----BEGIN PRIVATE KEY-----\n-----END',
    '-----END PRIVATE KEY-----',
    'https://a:a@',
    'https://a:aaaa@a.a',
    'ftp://a:b@a-a.',
    'postgres://',
    'postgres://a:',
    'postgres://a:b@',
    'postgres://a:b@h/',
    'postgres://a:b@h?',
    'mongodb+srv://a:b@',
    'jdbc:mysql://a:b@h/d?',
    'https://hooks.slack.com/services/T',
    'https://hooks.slack.com/services/Ta/Ba/',
    'aws_secret_access_key=',
    'aws_account_id:',
    '"aws_secret_access_key": "',
    'AKIAAAAAAAAAAAAAAAAA',
    'sk-proj-',
    'T3BlbkFJ',
    '\u00e9ghp_',
    '\ud835\udc00ghp_',
];

/** One valid-looking sample of a `token` shape (each run once at its minimum), so the shape is attacked
 *  from its own prefixes, runs and separators; and the shape's prefix alone. */
function tokenUnits(spec: SpecDir): string[] {
    return spec.rules.full.flatMap((rule) => {
        if (rule.kind !== 'token') return [];
        const parts = rule.parts as Array<Record<string, unknown>>;
        const sample = parts
            .map((part) => {
                if (typeof part.lit === 'string') return part.lit;
                if (Array.isArray(part.alt)) return String(part.alt[0]);
                if (typeof part.runClass === 'string')
                    return firstUnit(part.runClass).repeat(Number(part.min) || 1);
                return '';
            })
            .join('');
        return [
            sample,
            sample.slice(0, sample.length - 1),
            ...parts.flatMap((part) => (typeof part.lit === 'string' ? [part.lit] : [])),
        ];
    });
}

function firstUnit(classSource: string): string {
    const body = classSource.slice(1, -1);
    return body[0] === '\\' ? (body[1] as string) : (body[0] as string);
}

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

type Part = Record<string, unknown>;

const isVariableRun = (part: Part): boolean =>
    typeof part.runClass === 'string' && (part.min !== part.max || part.tails !== undefined);

function sampleOf(part: Part): string {
    if (typeof part.lit === 'string') return part.lit;
    if (Array.isArray(part.alt)) return String(part.alt[0]);
    if (typeof part.runClass === 'string') return firstUnit(part.runClass).repeat(Number(part.min) || 1);
    return '';
}

/** A shape with two variable runs of one class: its short cluster (the shape up to the first of them, repeated)
 *  followed by a long run of the second one. A run memory per class measures that long run again at every start
 *  of the cluster; a memory per part measures it once. */
function compositeAttacks(spec: SpecDir): Attack[] {
    return spec.rules.full.flatMap((rule) => {
        if (rule.kind !== 'token') return [];
        const parts = rule.parts as Part[];
        const first = parts.findIndex(
            (part, at) =>
                isVariableRun(part) &&
                parts.slice(at + 1).some((later) => isVariableRun(later) && later.runClass === part.runClass),
        );
        if (first === -1) return [];
        const cluster = parts.slice(0, first).map(sampleOf).join('');
        const separator = typeof parts[first + 1]?.lit === 'string' ? String(parts[first + 1]?.lit) : '';
        const head = cluster.repeat(CLUSTER_STARTS) + separator;
        const unit = firstUnit(String(parts[first]?.runClass));
        return [
            { name: `${String(rule.id)} cluster ${JSON.stringify(cluster)} then a long run`, unit, head },
        ];
    });
}

export function attacksFor(spec: SpecDir): Attack[] {
    const units = [...new Set([...FIXED_UNITS, ...wordUnits(spec), ...tokenUnits(spec)])];
    return [...units.map((unit) => ({ name: JSON.stringify(unit), unit })), ...compositeAttacks(spec)];
}
