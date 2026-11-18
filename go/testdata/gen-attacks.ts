#!/usr/bin/env bun
/**
 * Writes `attacks.json`, the attack units of the scaling test (tools/lib/attacks.ts), for the
 * Go scaling test. Run: bun go/testdata/gen-attacks.ts
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { attacksFor } from '../../tools/lib/attacks.ts';
import { readSpecDir } from '../../tools/lib/spec-patterns.ts';

const here = import.meta.dir;
// Composite attacks (a head, then the unit) need the text builder of the TypeScript scaling run; only plain units here.
const units = attacksFor(readSpecDir(join(here, '..', '..', 'spec')))
    .filter((attack) => attack.head === undefined)
    .map((attack) => attack.unit);
writeFileSync(join(here, 'attacks.json'), `${JSON.stringify(units, null, 1)}\n`);
console.log(`wrote ${units.length} attack units`);
