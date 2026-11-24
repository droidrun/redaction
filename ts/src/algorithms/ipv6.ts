/**
 * ipv6 — the `ipv6` check of the `regex` rule (SPEC 5.8): is a run of hexadecimal digits and colons the
 * text form of an IPv6 address (RFC 4291 section 2.2, RFC 5952).
 */
const HEX_GROUP = /^[0-9A-Fa-f]{1,4}$/;
const GROUPS = 8;

function countColons(text: string): number {
    return text.split(':').length - 1;
}

function areGroups(part: string): boolean {
    return part.split(':').every((group) => HEX_GROUP.test(group));
}

/** The groups of one side of `::`: none for an empty side, else every group must be valid. */
function sideGroups(side: string): number {
    if (side === '') return 0;
    return areGroups(side) ? side.split(':').length : Number.POSITIVE_INFINITY;
}

/** `minColons` is how many colons the text needs at least (a bare text needs more than a bracketed one). */
export function isIpv6(text: string, minColons: number): boolean {
    if (countColons(text) < minColons) return false;
    const parts = text.split('::');
    if (parts.length === 1) return countColons(text) === GROUPS - 1 && areGroups(text);
    if (parts.length !== 2) return false;
    const listed = sideGroups(parts[0] as string) + sideGroups(parts[1] as string);
    return listed < GROUPS;
}
