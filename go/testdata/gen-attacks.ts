#!/usr/bin/env bun
/**
 * Writes `attacks.json`, the attacks of the scaling test (tools/lib/attacks.ts), for the Go scaling test:
 * a list of `{name, unit, head?}`. A plain attack is the unit repeated to the size; a composite one (with a
 * `head`) starts with a short cluster and then repeats the unit (see `attackText`). Run:
 * bun go/testdata/gen-attacks.ts
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { attacksFor } from '../../tools/lib/attacks.ts';
import { readSpecDir } from '../../tools/lib/spec-patterns.ts';

const here = import.meta.dir;
const attacks = attacksFor(readSpecDir(join(here, '..', '..', 'spec')));
const lines = attacks.map((attack) => JSON.stringify(attack)).join(',\n');
writeFileSync(join(here, 'attacks.json'), `[\n${lines}\n]\n`);
const composite = attacks.filter((attack) => attack.head !== undefined).length;
console.log(`wrote ${attacks.length} attacks (${composite} composite)`);
