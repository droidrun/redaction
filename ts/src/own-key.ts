/**
 * own-key.ts — set a plain own property, whatever the key. Assignment with
 * the key `__proto__` would change the object's prototype instead (and drop
 * the key from the output); `defineProperty` keeps it an ordinary key.
 */
export function setOwnKey(target: Record<string, unknown>, key: string, value: unknown): void {
    Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}
