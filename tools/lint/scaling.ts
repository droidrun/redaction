/**
 * Scaling run (JS): reads {patterns, attacks, sizes, runs} from stdin, runs every pattern over
 * every attack string at every size and prints the best time per run as JSON. Run by lint-spec
 * in a subprocess under an external deadline, because a catastrophic pattern would not return.
 */
import { attackText, type Attack } from '../lib/attacks.ts';

export type Payload = {
    patterns: Array<{ where: string; source: string }>;
    attacks: Attack[];
    sizes: number[];
    runs: number;
};

function scan(pattern: RegExp, text: string): void {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
        if (match[0].length === 0) pattern.lastIndex += 1;
    }
}

const payload = JSON.parse(await Bun.stdin.text()) as Payload;
const results: Array<{ where: string; attack: string; size: number; ms: number }> = [];
for (const { where, source } of payload.patterns) {
    const pattern = new RegExp(source, 'g');
    for (const attack of payload.attacks) {
        for (const size of payload.sizes) {
            const text = attackText(attack, size);
            let best = Number.POSITIVE_INFINITY;
            for (let run = 0; run < payload.runs; run++) {
                const started = performance.now();
                scan(pattern, text);
                best = Math.min(best, performance.now() - started);
            }
            results.push({ where, attack: attack.name, size, ms: best });
        }
    }
}
console.log(JSON.stringify(results));
