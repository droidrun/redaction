/**
 * perf.test.ts — the latency budget for a list response: 1,000 realistic
 * action rows (about 0.5 MB of JSON, a third of them with a fake secret).
 *
 * Measured on an Apple-silicon laptop (bun 1.4): sync about 20 ms, async about
 * 75 ms per list, after one warm-up call. The budgets below leave roughly
 * 12x (sync) and 20x (async) headroom for slow CI runners and a cold JIT; a
 * regression that breaks the budget is a real algorithmic change, not noise.
 * The median of five runs is compared, not the best or the worst.
 */
import { expect, test } from 'bun:test';
import { redactJsonValue, redactJsonValueSync } from './index.js';
import { buildActions } from './perf.fixture.js';

const ITEMS = 1_000;
const RUNS = 5;
const SYNC_BUDGET_MS = 250;
const ASYNC_BUDGET_MS = 1_500;

function median(values: number[]): number {
    const sorted = [...values].sort((a, b) => a - b);
    return sorted[Math.floor(sorted.length / 2)] as number;
}

test(`sync: ${ITEMS} action rows stay under ${SYNC_BUDGET_MS} ms (median of ${RUNS})`, () => {
    const actions = buildActions(ITEMS);
    redactJsonValueSync(actions);
    const durations: number[] = [];
    for (let run = 0; run < RUNS; run++) {
        const started = performance.now();
        redactJsonValueSync(actions);
        durations.push(performance.now() - started);
    }
    expect(median(durations)).toBeLessThan(SYNC_BUDGET_MS);
});

test(`async: ${ITEMS} action rows stay under ${ASYNC_BUDGET_MS} ms (median of ${RUNS})`, async () => {
    const actions = buildActions(ITEMS);
    await redactJsonValue(actions, { hits: [] });
    const durations: number[] = [];
    for (let run = 0; run < RUNS; run++) {
        const started = performance.now();
        await redactJsonValue(actions, { hits: [] });
        durations.push(performance.now() - started);
    }
    expect(median(durations)).toBeLessThan(ASYNC_BUDGET_MS);
});

test('the fixture really holds secrets and both paths remove them', async () => {
    const actions = buildActions(ITEMS);
    const raw = JSON.stringify(actions);
    expect(raw).toContain('Zq9fake');
    expect(raw).toContain('Bearer eyJ');
    for (const out of [redactJsonValueSync(actions), await redactJsonValue(actions, { hits: [] })]) {
        const text = JSON.stringify(out);
        expect(text).not.toContain('Zq9fake');
        expect(text).not.toContain('Bearer eyJ');
        expect(text).not.toContain('k_live_');
        expect(text).toContain('[REDACTED:');
    }
});
