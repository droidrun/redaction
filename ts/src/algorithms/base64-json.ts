/**
 * base64-json — the 1Password service-account check (SPEC 5.7): the token body is base64 whose bytes, read as
 * Latin-1 text, are one JSON object or array. Own decoder and own JSON syntax check, so every language gives
 * the same answer (no library dialects: `NaN`, trailing garbage, depth limits).
 */
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const SEXTET_BITS = 6;
const BYTE_BITS = 8;
const GROUP = 4;
const PAD = '=';

const TAB = 0x09;
const LINE_FEED = 0x0a;
const CARRIAGE_RETURN = 0x0d;
const SPACE = 0x20;
const QUOTE = 0x22;
const BACKSLASH = 0x5c;

const BYTE_OF = new Map([...BASE64_ALPHABET].map((char, index) => [char, index]));

/** Forgiving base64 decode (WHATWG): up to two trailing `=` only when the length is a multiple of 4. */
export function decodeBase64(input: string): number[] | undefined {
    let data = input;
    if (data.length % GROUP === 0) {
        if (data.endsWith(PAD + PAD)) data = data.slice(0, -2);
        else if (data.endsWith(PAD)) data = data.slice(0, -1);
    }
    if (data.length % GROUP === 1) return undefined;
    const bytes: number[] = [];
    let buffer = 0;
    let bits = 0;
    for (const char of data) {
        const sextet = BYTE_OF.get(char);
        if (sextet === undefined) return undefined;
        buffer = (buffer << SEXTET_BITS) | sextet;
        bits += SEXTET_BITS;
        if (bits >= BYTE_BITS) {
            bits -= BYTE_BITS;
            bytes.push((buffer >> bits) & 0xff);
            buffer &= (1 << bits) - 1;
        }
    }
    return bytes;
}

const isDigit = (byte: number): boolean => byte >= 0x30 && byte <= 0x39;
const isHex = (byte: number): boolean =>
    isDigit(byte) || (byte >= 0x41 && byte <= 0x46) || (byte >= 0x61 && byte <= 0x66);
const isWhitespace = (byte: number): boolean =>
    byte === SPACE || byte === TAB || byte === LINE_FEED || byte === CARRIAGE_RETURN;
const ESCAPES = new Set([...'"\\/bfnrt'].map((char) => char.charCodeAt(0)));
const LITERALS = ['true', 'false', 'null'].map((word) => [...word].map((char) => char.charCodeAt(0)));

class JsonScanner {
    position = 0;
    constructor(private readonly bytes: number[]) {}

    peek(): number {
        return this.bytes[this.position] ?? -1;
    }

    skipWhitespace(): void {
        while (isWhitespace(this.peek())) this.position += 1;
    }

    string(): boolean {
        this.position += 1;
        for (;;) {
            const byte = this.peek();
            this.position += 1;
            if (byte === -1 || byte < SPACE) return false;
            if (byte === QUOTE) return true;
            if (byte !== BACKSLASH) continue;
            const escape = this.peek();
            this.position += 1;
            if (escape === 0x75) {
                for (let digit = 0; digit < GROUP; digit++) {
                    if (!isHex(this.peek())) return false;
                    this.position += 1;
                }
            } else if (!ESCAPES.has(escape)) return false;
        }
    }

    digits(): boolean {
        if (!isDigit(this.peek())) return false;
        while (isDigit(this.peek())) this.position += 1;
        return true;
    }

    number(): boolean {
        if (this.peek() === 0x2d) this.position += 1;
        if (this.peek() === 0x30) this.position += 1;
        else if (!this.digits()) return false;
        if (this.peek() === 0x2e) {
            this.position += 1;
            if (!this.digits()) return false;
        }
        if (this.peek() === 0x65 || this.peek() === 0x45) {
            this.position += 1;
            if (this.peek() === 0x2b || this.peek() === 0x2d) this.position += 1;
            if (!this.digits()) return false;
        }
        return true;
    }

    literal(): boolean {
        const word = LITERALS.find((candidate) =>
            candidate.every((byte, index) => this.bytes[this.position + index] === byte),
        );
        if (word === undefined) return false;
        this.position += word.length;
        return true;
    }
}

const OPEN_OBJECT = 0x7b;
const CLOSE_OBJECT = 0x7d;
const OPEN_ARRAY = 0x5b;
const CLOSE_ARRAY = 0x5d;
const COMMA = 0x2c;
const COLON = 0x3a;
const MINUS = 0x2d;

/** `"key"` and `:`, the start of an object member. */
function objectKey(scanner: JsonScanner): boolean {
    scanner.skipWhitespace();
    if (scanner.peek() !== QUOTE || !scanner.string()) return false;
    scanner.skipWhitespace();
    if (scanner.peek() !== COLON) return false;
    scanner.position += 1;
    return true;
}

function scalar(scanner: JsonScanner): boolean {
    const byte = scanner.peek();
    if (byte === QUOTE) return scanner.string();
    if (byte === MINUS || isDigit(byte)) return scanner.number();
    return scanner.literal();
}

/** After an opening bracket: an empty container closes at once, else the first member (or value) starts. */
function openContainer(scanner: JsonScanner, stack: boolean[], open: number): 'closed' | 'value' | 'bad' {
    const isObject = open === OPEN_OBJECT;
    scanner.position += 1;
    stack.push(isObject);
    scanner.skipWhitespace();
    if (scanner.peek() === (isObject ? CLOSE_OBJECT : CLOSE_ARRAY)) {
        scanner.position += 1;
        stack.pop();
        return 'closed';
    }
    if (isObject && !objectKey(scanner)) return 'bad';
    return 'value';
}

/** After a value: `,` and the next member, or the closing bracket of the innermost container. */
function afterValue(scanner: JsonScanner, stack: boolean[]): 'value' | 'closed' | 'bad' {
    const inObject = stack[stack.length - 1] as boolean;
    const byte = scanner.peek();
    if (byte === COMMA) {
        scanner.position += 1;
        return inObject && !objectKey(scanner) ? 'bad' : 'value';
    }
    if (byte !== (inObject ? CLOSE_OBJECT : CLOSE_ARRAY)) return 'bad';
    scanner.position += 1;
    stack.pop();
    return 'closed';
}

/** True when `bytes` (one unit per byte) are one JSON text (ECMA-404) whose top value is an object or array.
 *  Iterative: the stack holds the open containers (`true` = object). */
export function isJsonContainer(bytes: number[]): boolean {
    const scanner = new JsonScanner(bytes);
    scanner.skipWhitespace();
    if (scanner.peek() !== OPEN_OBJECT && scanner.peek() !== OPEN_ARRAY) return false;
    const stack: boolean[] = [];
    let expectValue = true;
    while (expectValue || stack.length > 0) {
        scanner.skipWhitespace();
        const byte = scanner.peek();
        const isOpen = byte === OPEN_OBJECT || byte === OPEN_ARRAY;
        let step: 'value' | 'closed' | 'bad';
        if (!expectValue) step = afterValue(scanner, stack);
        else if (isOpen) step = openContainer(scanner, stack, byte);
        else step = scalar(scanner) ? 'closed' : 'bad';
        if (step === 'bad') return false;
        expectValue = step === 'value';
    }
    scanner.skipWhitespace();
    return scanner.peek() === -1;
}

/** True when `token` decodes as base64 to bytes that, read as Latin-1, are a JSON object or array. */
export function isBase64Json(token: string): boolean {
    const bytes = decodeBase64(token);
    return bytes !== undefined && isJsonContainer(bytes);
}
