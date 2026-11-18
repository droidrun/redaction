/** Seeded generator shared by the corpus families (mulberry32, 32-bit state). */
export function mulberry32(seed: number): () => number {
    let a = seed;
    return () => {
        a = (a + 0x6d2b79f5) | 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

export type Rng = ReturnType<typeof mulberry32>;

export function pick<T>(rng: Rng, items: readonly T[]): T {
    return items[Math.floor(rng() * items.length)] as T;
}

export function chars(rng: Rng, alphabet: string, length: number): string {
    const units = [...alphabet];
    let out = '';
    for (let i = 0; i < length; i++) out += pick(rng, units);
    return out;
}

export const BASE62 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
export const KEY_ALPHABET = `${BASE62}_-`;
export const HEX = '0123456789abcdef';
