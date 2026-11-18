#!/usr/bin/env bun
/**
 * TypeScript runner of the cross-language differential test (protocol: protocol.ts). Reads requests on stdin,
 * writes responses on stdout; the first line is its capabilities (both tiers, both modes).
 */
import {
    redactJsonValue,
    redactJsonValueSync,
    redactText,
    redactTextSync,
    shortenRuleId,
    type Hit,
} from '../../ts/src/index.ts';
import { lines, toLine, type Request } from './protocol.ts';

function counts(hits: readonly Hit[]): Array<[string, number]> {
    const totals = new Map<string, number>();
    for (const hit of hits) {
        const id = shortenRuleId(hit.ruleId);
        totals.set(id, (totals.get(id) ?? 0) + 1);
    }
    return [...totals];
}

async function redact(request: Request): Promise<{ out: unknown; hits: Hit[] }> {
    const { mode, opts } = request;
    const skipKeys = opts.skipKeys === undefined ? {} : { skipKeys: new Set(opts.skipKeys) };
    const limits = {
        mode,
        maxDepth: opts.maxDepth,
        maxNodes: opts.maxNodes,
        maxChars: opts.maxChars,
        ...skipKeys,
    };
    const stats = { hits: [] as Hit[] };
    if (request.kind === 'text') {
        const text = request.input as string;
        if (request.tier === 'standard') {
            const result = redactTextSync(text, { mode, maxChars: opts.maxChars });
            return { out: result.text, hits: result.hits };
        }
        const result = await redactText(text, { mode, maxChars: opts.maxChars });
        return { out: result.text, hits: result.hits };
    }
    if (request.tier === 'standard') {
        const out = redactJsonValueSync(request.input, { ...limits, stats });
        return { out, hits: stats.hits };
    }
    const out = await redactJsonValue(request.input, stats, limits);
    return { out, hits: stats.hits };
}

async function respond(line: string): Promise<string> {
    const request = JSON.parse(line) as Request;
    try {
        const { out, hits } = await redact(request);
        return toLine({ id: request.id, out, hits: counts(hits), error: null, crash: null });
    } catch (error) {
        const name = error instanceof Error ? error.constructor.name : typeof error;
        return toLine({ id: request.id, out: null, hits: [], error: null, crash: name });
    }
}

const both = ['compat', 'strict'];
process.stdout.write(`${JSON.stringify({ capabilities: { standard: both, full: both } })}\n`);
for await (const line of lines(process.stdin)) {
    if (line.trim() !== '') process.stdout.write(`${await respond(line)}\n`);
}
