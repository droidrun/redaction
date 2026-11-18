/**
 * The oracle of the full-tier parity tests: `@secretlint/core` 13.0.4 with the preset
 * `@secretlint/secretlint-rule-preset-recommend` 13.0.4 (both dev dependencies, never loaded by the package),
 * configured as the package used to run them: every preset rule but `filter-comments`, AWS ID scanning on,
 * the content handed over as `message.txt`.
 */
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { lintSource } from '@secretlint/core';
import { creator as presetRecommend } from '@secretlint/secretlint-rule-preset-recommend';

export type OracleHit = {
    ruleId: string;
    range: [number, number];
    messageId: string;
    /** `data.KEY` of an AWS secret access key report (the secret itself). */
    secret?: string;
};

/**
 * `@secretlint/core` keeps every performance mark of every call in one process-wide profiler and scans that list
 * on each new mark, so thousands of calls turn quadratic. The profiler is cleared after each call (the oracle
 * needs the reports, not the timings). It is resolved from core's own location, so it is core's instance.
 */
const corePath = fileURLToPath(import.meta.resolve('@secretlint/core'));
const profilerPath = createRequire(corePath).resolve('@secretlint/profiler');
const { secretLintProfiler } = (await import(profilerPath)) as {
    secretLintProfiler: { entries: unknown[]; measures: unknown[]; executionPromises: unknown[] };
};

const RULE_PREFIX = '@secretlint/secretlint-rule-';
const BOM = '﻿';

const rules = presetRecommend.rules
    .filter((rule) => rule.meta.id !== `${RULE_PREFIX}filter-comments`)
    .map((rule) => ({
        id: rule.meta.id,
        rule,
        options: rule.meta.id === `${RULE_PREFIX}aws` ? { enableIDScanRule: true } : {},
    }));

/** What the upstream rules report for `content` (ranges relative to `content`, including a leading BOM). */
export async function oracleHits(content: string): Promise<OracleHit[]> {
    const result = await lintSource({
        source: { filePath: 'message.txt', content, ext: '.txt', contentType: 'text' },
        options: { config: { rules } },
    });
    await new Promise((resolve) => setImmediate(resolve));
    secretLintProfiler.entries.length = 0;
    secretLintProfiler.measures.length = 0;
    secretLintProfiler.executionPromises.length = 0;
    performance.clearMarks();
    performance.clearMeasures();
    const offset = content.startsWith(BOM) ? 1 : 0;
    return result.messages.map((message) => {
        const data = message.data as { KEY?: string } | undefined;
        return {
            ruleId: message.ruleId.slice(RULE_PREFIX.length),
            range: [message.range[0] + offset, message.range[1] + offset],
            messageId: String(message.messageId),
            ...(message.messageId === 'AWSSecretAccessKey' ? { secret: data?.KEY } : {}),
        };
    });
}

/**
 * The documented deviation of the AWS secret access key (Lutz L-K, SPEC 4.1): upstream reports
 * `[match start, match start + 40]`, which begins at the key name; the full tier reports the 40 units of the
 * secret. The secret follows the key name, so its first occurrence at or after the match start is the value.
 */
export function withAwsCorrection(hits: OracleHit[], content: string): Array<[string, number, number]> {
    return hits.map((hit) => {
        if (hit.secret === undefined) return [hit.ruleId, hit.range[0], hit.range[1]];
        const start = content.indexOf(hit.secret, hit.range[0]);
        return [hit.ruleId, start, start + hit.secret.length];
    });
}
