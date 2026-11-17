/**
 * adversarial.test.ts — worst-case inputs for the sync rules. Each case is a
 * text built to make a backtracking or rescanning rule do quadratic work; the
 * budget is a literal per case (ms, median of 3 after a warm-up) with large
 * headroom over the measured time (see wave notes), so a regression to a
 * quadratic rule fails by orders of magnitude, not by noise.
 */
import { expect, test } from 'bun:test';
import { redactJsonValueSync, redactTextSync } from './index.js';

const KB = 1024;

const CASES: Array<[name: string, text: string, budgetMs: number]> = [
    ['a_token=a_token= x 64 KB', 'a_token='.repeat(8 * KB), 250],
    ['password= x 20000', 'password='.repeat(20_000), 250],
    ['secret:secret: x 10000', 'secret:secret:'.repeat(10_000), 250],
    ['unterminated password=" x 20000', 'password="'.repeat(20_000), 250],
    ['password=\' with no closing quote anywhere', `password='${'x y '.repeat(30_000)}`, 250],
    ['one long hyphenated run', 'a-'.repeat(100 * KB), 250],
    ['token=token=token= (value is a label)', 'token='.repeat(20_000), 250],
    ['bearer x 20000', 'Bearer '.repeat(20_000), 250],
    ['basic AAAAAAAA x 8000', 'Basic AAAAAAAAAAAA '.repeat(8_000), 250],
    ['PEM headers back to back', '-----BEGIN PRIVATE KEY-----'.repeat(3_000), 250],
    ['PEM header + 1 MB of body-looking text', `-----BEGIN PRIVATE KEY-----${'ab cd '.repeat(150_000)}`, 250],
    ['query ?a=?a=?a= x 20000', '?a='.repeat(20_000), 250],
    ['query with percent values', '?a=%41%42&'.repeat(10_000), 250],
    ['query token= x 10000', '?token=?token='.repeat(10_000), 250],
    ['cookie: x 20000', 'Cookie:'.repeat(20_000), 250],
    ['url userinfo scheme:// x 10000', 'a://u:'.repeat(10_000), 250],
    ['escaped quotes \\" x 30000', '\\"'.repeat(30_000), 250],
    ['password with 10000 backslashes', `password=${'\\'.repeat(10_000)}x`, 250],
    ['ghp_ prefixes', 'ghp_'.repeat(20_000), 250],
    ['eyJ prefixes', 'eyJ'.repeat(20_000), 250],
    ['sk- prefixes', 'sk-'.repeat(20_000), 250],
];

function medianMs(run: () => void): number {
    run();
    const times: number[] = [];
    for (let i = 0; i < 3; i++) {
        const started = performance.now();
        run();
        times.push(performance.now() - started);
    }
    return [...times].sort((a, b) => a - b)[1] as number;
}

test.each(CASES)('%s stays under its budget', (_name, text, budgetMs) => {
    expect(medianMs(() => redactTextSync(text))).toBeLessThan(budgetMs);
});

test('the same texts as JSON string leaves and as keys stay under budget too', () => {
    const value = Object.fromEntries(CASES.slice(0, 6).map(([name, text]) => [name, text]));
    expect(medianMs(() => redactJsonValueSync(value))).toBeLessThan(600);
});
