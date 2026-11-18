/**
 * Scaling run through the interpreter (JS): reads {attacks, sizes} from stdin, runs `detectSyncHits` and `detectFullHits` (every
 * rule kind with its restart loops, not only the raw patterns) over every attack string at every size and
 * prints the time per run as JSON. Run by lint-spec in a subprocess under an external deadline.
 */
import { detectFullHits } from '../../ts/src/full-rules.ts';
import { detectSyncHits } from '../../ts/src/sync-rules.ts';

type Payload = { attacks: Array<{ name: string; unit: string }>; sizes: number[] };

const payload = JSON.parse(await Bun.stdin.text()) as Payload;
const results: Array<{ where: string; attack: string; size: number; ms: number }> = [];
for (const attack of payload.attacks) {
    for (const size of payload.sizes) {
        const text = attack.unit.repeat(Math.ceil(size / attack.unit.length)).slice(0, size);
        const started = performance.now();
        detectSyncHits(text);
        detectFullHits(text);
        results.push({ where: 'detect', attack: attack.name, size, ms: performance.now() - started });
    }
}
console.log(JSON.stringify(results));
