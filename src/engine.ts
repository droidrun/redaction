/**
 * Run the fixed, flattened scanner list without importing secretlint/core
 * (which loads a process-wide profiler). Only ruleId + range leave this layer.
 * The pinned scanners use content/filePath/ext, report, and translation;
 * the comment filter that needs source-location helpers is excluded.
 * Exact 13.0.4 pins for preset-recommend and types are load-bearing;
 * dependency bumps require the parity and rule-shape guard tests to pass.
 */
import type {
    SecretLintCoreConfigRule,
    SecretLintRuleContext,
    SecretLintRuleIgnoreDescriptor,
    SecretLintRuleLocalizeMessages,
    SecretLintRuleMessageTranslate,
    SecretLintSourceCode,
} from '@secretlint/types';
import { RULES } from './rules/index.js';

export type EngineHit = { ruleId: string; range: readonly [number, number] };
type Report = EngineHit & { message: string };

function createTranslator<T extends SecretLintRuleLocalizeMessages>(
    messages: T,
): SecretLintRuleMessageTranslate<T> {
    return (messageId, props) => {
        const localized = messages[messageId];
        if (!localized) throw new Error('Unknown rule message id');
        return { message: localized.en(props), messageId: String(messageId), data: props };
    };
}

function isIgnored(report: Report, ignored: SecretLintRuleIgnoreDescriptor): boolean {
    const containsRange = ignored.range[0] <= report.range[0] && report.range[1] <= ignored.range[1];
    const matchesRule = !ignored.targetRuleId || ignored.targetRuleId === '*' ||
        ignored.targetRuleId === report.ruleId;
    return containsRange && matchesRule;
}

function isDuplicate(report: Report, other: Report): boolean {
    const sameRange = report.range[0] === other.range[0] && report.range[1] === other.range[1];
    return sameRange && report.message === other.message;
}

function supportsText({ rule }: SecretLintCoreConfigRule): boolean {
    const contentTypes = rule.meta.supportedContentTypes;
    return contentTypes.includes('text') || contentTypes.includes('all');
}

/** Unconditional scan. The caller owns windowing and fail-open handling. */
export async function scanText(content: string): Promise<EngineHit[]> {
    const hasBOM = content.charCodeAt(0) === 0xfeff;
    const bomOffset = hasBOM ? 1 : 0;
    // Like core, strip the BOM before the rules run. The fixed scanner list
    // never uses the source-location methods on SecretLintSourceCode.
    const source = {
        content: hasBOM ? content.slice(1) : content,
        hasBOM,
        filePath: 'message.txt',
        physicalFilePath: 'message.txt',
        ext: '.txt',
        contentType: 'text',
    } as SecretLintSourceCode;
    const reports: Report[] = [];
    const ignores: SecretLintRuleIgnoreDescriptor[] = [];
    await Promise.all(RULES.filter(supportsText).map(async ({ id, rule, options }) => {
        const context: SecretLintRuleContext = {
            sharedOptions: {},
            createTranslator,
            report: ({ range, message }) => {
                reports.push({ ruleId: id, range, message: message.message });
            },
            ignore: (descriptor) => {
                ignores.push(descriptor);
            },
        };
        await rule.create(context, options ?? {}).file?.(source);
    }));
    const visible = reports.filter((report) => !ignores.some((ignored) => isIgnored(report, ignored)));
    return visible
        // Core keeps the last duplicate (same range, message, and severity).
        // All configured rules use its default "error" severity.
        .filter((report, index) => !visible.slice(index + 1).some((other) => isDuplicate(report, other)))
        .sort((a, b) => a.range[0] - b.range[0] || a.range[1] - b.range[1])
        // Unlike core, return ranges relative to the caller's input, including its BOM.
        .map(({ ruleId, range }) => ({ ruleId, range: [range[0] + bomOffset, range[1] + bomOffset] }));
}
