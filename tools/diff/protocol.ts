/**
 * The JSONL protocol of the cross-language differential test.
 *
 * One request per line on a runner's stdin, one response per line on its stdout, matched by `id`:
 *
 *   request:  { id, kind: 'text' | 'json', tier: 'standard' | 'full', mode: 'compat' | 'strict',
 *               opts, input }
 *   response: { id, out, hits: [[ruleId, count], ...], error }
 *
 * The first line a runner writes is `{"capabilities": {"standard": [modes], "full": [modes]}}`: the
 * driver only sends a (tier, mode) a runner lists, so a tier a language does not have yet is skipped,
 * and shows up by itself when the language gets it. `opts` holds `maxChars`, `maxDepth`, `maxNodes`,
 * `skipKeys` (all optional). `out` is the redacted text (a JSON string) or value. `hits` counts hits
 * per rule id (never ranges). `error` is `null` or the class name of a failure of the call; it is not
 * compared (the languages report fail-closed events differently), the output is.
 *
 * Output is compared as parsed JSON in which object key order counts, numbers are compared as doubles
 * and strings as UTF-16 (a lone surrogate must come back as that lone surrogate). Hits are compared as
 * rule-id counts.
 */
export type Tier = 'standard' | 'full';
export type Mode = 'compat' | 'strict';
export type Kind = 'text' | 'json';

export type RequestOpts = { maxChars?: number; maxDepth?: number; maxNodes?: number; skipKeys?: string[] };

export type Request = {
    id: string;
    kind: Kind;
    tier: Tier;
    mode: Mode;
    opts: RequestOpts;
    input: unknown;
};

export type Response = { id: string; out: unknown; hits: Array<[string, number]>; error: string | null };
export type Capabilities = Record<Tier, Mode[]>;

/** `JSON.stringify` of a request or response on one line: U+2028 and U+2029 are written as escapes, so that
 *  no line splitter that treats them as line ends (readline does) can cut a line. */
export function toLine(value: unknown): string {
    return JSON.stringify(value)
        .replace(/\u2028/g, '\\u2028')
        .replace(/\u2029/g, '\\u2029');
}

/** The lines of a stream of text chunks, split at `\n` only. */
export async function* lines(chunks: AsyncIterable<string | Uint8Array>): AsyncGenerator<string> {
    const decoder = new TextDecoder();
    let rest = '';
    for await (const chunk of chunks) {
        rest += typeof chunk === 'string' ? chunk : decoder.decode(chunk, { stream: true });
        for (let end = rest.indexOf('\n'); end !== -1; end = rest.indexOf('\n')) {
            yield rest.slice(0, end);
            rest = rest.slice(end + 1);
        }
    }
    rest += decoder.decode();
    if (rest !== '') yield rest;
}

/** Hit counts by rule id, as a sorted `id=count` list (order of first occurrence does not count). */
export function countKey(hits: ReadonlyArray<readonly [string, number]>): string {
    const totals = new Map<string, number>();
    for (const [id, count] of hits) totals.set(id, (totals.get(id) ?? 0) + count);
    return [...totals]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([id, count]) => `${id}=${count}`)
        .join(',');
}

/**
 * Canonical text of a JSON document that keeps key order: parse the text with its own reader (JSON.parse
 * would put integer-like keys first and hide an order difference) and write it back with numbers as doubles.
 */
export function canonicalJson(text: string): string {
    const parser = new Reader(text);
    const out: string[] = [];
    parser.value(out);
    parser.end();
    return out.join('');
}

class Reader {
    private at = 0;
    constructor(private readonly text: string) {}

    end(): void {
        this.space();
        if (this.at !== this.text.length) throw new Error('trailing text in JSON');
    }

    private space(): void {
        while (' \t\n\r'.includes(this.text[this.at] ?? 'x')) this.at += 1;
    }

    value(out: string[]): void {
        this.space();
        const char = this.text[this.at];
        if (char === '{') return this.object(out);
        if (char === '[') return this.array(out);
        if (char === '"') return void out.push(JSON.stringify(this.string()));
        const word = /^(?:true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
            this.text.slice(this.at, this.at + 400),
        );
        if (!word) throw new Error('bad JSON value');
        this.at += word[0].length;
        out.push(/^[-\d]/.test(word[0]) ? this.number(word[0]) : word[0]);
    }

    private number(raw: string): string {
        const double = Number(raw);
        return Object.is(double, -0) ? '-0' : String(double);
    }

    private string(): string {
        const start = this.at;
        this.at += 1;
        while (this.text[this.at] !== '"') this.at += this.text[this.at] === '\\' ? 2 : 1;
        this.at += 1;
        // JSON.parse decodes the escapes of one string; a lone surrogate escape stays a lone surrogate.
        return JSON.parse(this.text.slice(start, this.at)) as string;
    }

    private object(out: string[]): void {
        out.push('{');
        this.at += 1;
        this.space();
        if (this.text[this.at] === '}') {
            this.at += 1;
            return void out.push('}');
        }
        for (let first = true; ; first = false) {
            if (!first) out.push(',');
            this.space();
            out.push(JSON.stringify(this.string()), ':');
            this.space();
            this.at += 1; // the colon
            this.value(out);
            this.space();
            const next = this.text[this.at];
            this.at += 1;
            if (next === '}') return void out.push('}');
        }
    }

    private array(out: string[]): void {
        out.push('[');
        this.at += 1;
        this.space();
        if (this.text[this.at] === ']') {
            this.at += 1;
            return void out.push(']');
        }
        for (let first = true; ; first = false) {
            if (!first) out.push(',');
            this.value(out);
            this.space();
            const next = this.text[this.at];
            this.at += 1;
            if (next === ']') return void out.push(']');
        }
    }
}
