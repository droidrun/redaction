// prepack: copy the conformance vectors of the repo's spec/ into the package, where the
// `./vectors/*.json` export serves them. Runs from `npm pack` / `pnpm publish`.
import { cpSync, existsSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const source = fileURLToPath(new URL('../../spec/vectors', import.meta.url));
const target = fileURLToPath(new URL('../vectors', import.meta.url));
if (!existsSync(source)) throw new Error('spec/vectors not found: pack from a checkout of the repository');
rmSync(target, { recursive: true, force: true });
cpSync(source, target, { recursive: true });
