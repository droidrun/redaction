/**
 * query-values — values of secret-named query parameters: the whole value (up to
 * `&`, `#`, whitespace or a quote, however long), including a `?`/`&` inside it. A
 * non-secret parameter whose percent-encoded value hides a secret parameter
 * (`redirect=…%3Ftoken%3D…`) is redacted whole. The decode work is budgeted per text.
 */
import { charTest, compile, foldLower, runEnd, type Range } from '../portable.js';
import { isSecretKeyName } from '../key-names.js';
import { isPlaceholderValue } from './placeholder-value.js';
import { percentDecode } from './query-value.js';
import type { Scanner } from './regex-rule.js';
import type { Rule } from '../spec.js';

type QueryRule = Rule & {
    queryKey: string;
    queryOnlyKeys: string[];
    valueEnd: string;
    nestedEnd: string;
    nestedLimit: number;
    decodeBudget: number;
    dropPlaceholder?: boolean;
};

export function prepareQueryValues(rule: QueryRule): Scanner {
    const loop = compile(rule.queryKey, 'g');
    const nested = compile(rule.queryKey, 'g');
    const endsValue = charTest(rule.valueEnd);
    const endsNested = charTest(rule.nestedEnd);
    const queryOnly = new Set(rule.queryOnlyKeys);
    const isSecretKey = (key: string): boolean => isSecretKeyName(key) || queryOnly.has(foldLower(key));
    const hasSecretParam = (decoded: string): boolean => {
        for (const match of decoded.matchAll(nested)) {
            if (isSecretKey(percentDecode(match[1] ?? ''))) return true;
        }
        return false;
    };
    return (text) => {
        const ranges: Range[] = [];
        let budget = rule.decodeBudget;
        loop.lastIndex = 0;
        for (let match = loop.exec(text); match !== null; match = loop.exec(text)) {
            const valueStart = loop.lastIndex;
            if (isSecretKey(percentDecode(match[1] ?? ''))) {
                const end = runEnd(text, valueStart, (unit) => !endsValue(unit));
                if (end > valueStart) ranges.push([valueStart, end]);
                loop.lastIndex = Math.max(valueStart, end);
                continue;
            }
            if (budget <= 0) continue;
            const end = runEnd(text, valueStart, (unit) => !endsNested(unit), rule.nestedLimit);
            budget -= end - valueStart;
            const raw = text.slice(valueStart, end);
            if (!raw.includes('%')) continue;
            const decoded = percentDecode(raw);
            if (decoded !== raw && hasSecretParam(`?${decoded}`)) ranges.push([valueStart, end]);
        }
        return rule.dropPlaceholder === true
            ? ranges.filter(([start, end]) => end > start && !isPlaceholderValue(text, start, end))
            : ranges;
    };
}
