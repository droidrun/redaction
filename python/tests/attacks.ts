/** Prints the attack units of tools/lib/attacks.ts for the spec directory as JSON: [{ name, unit, head? }]. */
import { join } from 'node:path';
import { attacksFor } from '../../tools/lib/attacks.ts';
import { readSpecDir } from '../../tools/lib/spec-patterns.ts';

const specDir = join(import.meta.dir, '..', '..', 'spec');
console.log(JSON.stringify(attacksFor(readSpecDir(specDir))));
