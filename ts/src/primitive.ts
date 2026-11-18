/** True for `null` and every value that is not an object or a function (strings, numbers, booleans, bigint, ...). */
export function isPrimitive(value: unknown): boolean {
    return value === null || (typeof value !== 'object' && typeof value !== 'function');
}
