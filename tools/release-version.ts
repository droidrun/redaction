#!/usr/bin/env bun
/**
 * release-version — one version for the three packages of this repository.
 *
 *   tools/release-version 0.3.0              set the version everywhere
 *   tools/release-version --check            fail (exit 1) unless every place holds the same version
 *   tools/release-version --check v0.3.0     ... and that version is the given tag (`vX.Y.Z`, or `go/vX.Y.Z`)
 *   tools/release-version --print            print the version (when all places agree)
 *
 * The places: `ts/package.json` (npm), `python/pyproject.toml` and the entry of the package in
 * `python/uv.lock` (so `uv sync --locked` keeps working), and the `Version` constant of
 * `go/version.go`. Only the version text is replaced; nothing else in the files is touched.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const ROOT = process.env.RELEASE_VERSION_ROOT ?? resolve(import.meta.dir, '..');
/** X.Y.Z where each number is 0 or has no leading zero (SemVer 2.0.0, without pre-release or build parts). */
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;

export function isVersion(text: string): boolean {
    return SEMVER.test(text);
}

type Place = { file: string; label: string; pattern: RegExp };

/** `pattern`: the text before the version is group 1, the version group 2, the text after group 3. */
const PLACES: Place[] = [
    { file: 'ts/package.json', label: 'npm', pattern: /^(\s*"version":\s*")([^"]+)(")/m },
    {
        file: 'python/pyproject.toml',
        label: 'python',
        pattern: /(\[project\][^[]*?\nversion\s*=\s*")([^"]+)(")/,
    },
    {
        file: 'python/uv.lock',
        label: 'python lock',
        pattern: /(\nname = "droidrun-redaction"\nversion = ")([^"]+)(")/,
    },
    { file: 'go/version.go', label: 'go', pattern: /(\nconst Version = ")([^"]+)(")/ },
];

function read(place: Place): { text: string; version: string } {
    const text = readFileSync(join(ROOT, place.file), 'utf8');
    const match = place.pattern.exec(text);
    if (!match) throw new Error(`${place.file}: no version found`);
    return { text, version: match[2] as string };
}

function versions(): Array<{ place: Place; version: string }> {
    return PLACES.map((place) => ({ place, version: read(place).version }));
}

function agreed(found: Array<{ place: Place; version: string }>): string | undefined {
    const distinct = new Set(found.map((entry) => entry.version));
    return distinct.size === 1 ? [...distinct][0] : undefined;
}

function check(tag: string | undefined): void {
    const found = versions();
    const table = found.map(
        (entry) => `  ${entry.place.label.padEnd(12)} ${entry.version}   (${entry.place.file})`,
    );
    const version = agreed(found);
    if (version === undefined) {
        console.error(`the versions differ:\n${table.join('\n')}`);
        process.exit(1);
    }
    if (!isVersion(version)) {
        console.error(`not a version of the form X.Y.Z: ${version}`);
        process.exit(1);
    }
    if (tag !== undefined && tag.replace(/^go\//, '') !== `v${version}`) {
        console.error(`the tag ${tag} is not v${version}, the version of all three packages`);
        process.exit(1);
    }
    console.log(`all versions are ${version}${tag === undefined ? '' : ` (tag ${tag})`}`);
}

function set(version: string): void {
    if (!isVersion(version)) {
        console.error('usage: tools/release-version X.Y.Z | --check [tag] | --print');
        process.exit(2);
    }
    for (const place of PLACES) {
        const { text } = read(place);
        writeFileSync(join(ROOT, place.file), text.replace(place.pattern, `$1${version}$3`));
    }
    check(undefined);
}

if (import.meta.main) {
    const [first, second] = process.argv.slice(2);
    if (first === '--check') check(second);
    else if (first === '--print') console.log(agreed(versions()) ?? process.exit(1));
    else set(first ?? '');
}
