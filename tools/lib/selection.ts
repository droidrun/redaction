/**
 * selection — what an `--only` list narrows: the patterns of the named rule ids or kinds, the attack units that
 * belong to them, and the interpreter scaling (which has no per-rule entry point, so it runs only over the
 * attack units of the selected rules and is skipped when there are none). Without a list nothing narrows.
 */
import { attacksFor, ruleAttacks, type Attack } from './attacks.ts';
import { isSelected, type NamedPattern, type SpecDir } from './spec-patterns.ts';

export type Scope = {
    patterns: NamedPattern[];
    attacks: Attack[];
    /** `undefined`: the interpreter scaling is skipped. */
    interpreterAttacks: Attack[] | undefined;
    skipped: string[];
};

export function scopeFor(spec: SpecDir, patterns: NamedPattern[], only: string[] | undefined): Scope {
    if (only === undefined) {
        const attacks = attacksFor(spec);
        return { patterns, attacks, interpreterAttacks: attacks, skipped: [] };
    }
    const keep = (rule: Record<string, unknown>): boolean =>
        isSelected({ id: String(rule.id), kind: String(rule.kind) }, only);
    const selected = patterns.filter((pattern) => isSelected(pattern.rule, only));
    const own = ruleAttacks(spec, keep);
    const left = patterns.length - selected.length;
    const skipped = [`--only ${only.join(',')}: ${left} of ${patterns.length} patterns skipped`];
    if (own.length === 0) skipped.push('--only: interpreter scaling skipped (no attack units belong to it)');
    return {
        patterns: selected,
        attacks: attacksFor(spec, keep),
        interpreterAttacks: own.length === 0 ? undefined : own,
        skipped,
    };
}

/** An `--only` name that matches no rule id and no rule kind of the spec. */
export function unknownOnly(patterns: NamedPattern[], only: string[]): string[] {
    return only
        .filter((name) => !patterns.some((pattern) => isSelected(pattern.rule, [name])))
        .map((name) => `--only: no rule id or kind named ${name}`);
}
