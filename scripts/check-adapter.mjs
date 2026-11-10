import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const read = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const manifest = read('module.json');
assert.equal(manifest.id, 'storage-bhpan');
assert.equal(manifest.implementation, 'library');
assert.deepEqual(manifest.required, []);
assert.deepEqual(manifest.optional, []);
const modulePath = 'github.com/StuHelper/stuhelper-storage-bhpan';
const imports = execFileSync('go', ['list', '-deps', '-test', '-f', '{{if not .Standard}}{{.ImportPath}}{{end}}', './...'], { env: { ...process.env, GOWORK: 'off' }, encoding: 'utf8' }).trim().split(/\r?\n/).filter(Boolean);
assert(imports.length > 0);
for (const name of imports) assert(name === modulePath || name.startsWith(`${modulePath}/`) || name.startsWith(`${modulePath} `) || name.startsWith(`${modulePath}_test`) || name === `${modulePath}.test`, `Unexpected Go dependency: ${name}`);
const specifications = manifest.specifications.map(file => fs.readFileSync(file, 'utf8')).join('\n');
for (const [scenario, references] of Object.entries(manifest.scenario_tests)) {
  assert(specifications.includes(`| ${scenario} |`), `Unknown scenario: ${scenario}`);
  assert(references.length > 0);
  for (const reference of references) {
    const [file, name] = reference.split('#');
    assert(/^[a-z_]+_test\.go$/.test(file));
    assert(/^Test[A-Za-z0-9]+$/.test(name));
    assert(fs.readFileSync(file, 'utf8').includes(`func ${name}(t *testing.T)`), `Missing test: ${reference}`);
  }
}
const bytes = fs.readFileSync('contracts/bhpan.openapi.json');
const contract = JSON.parse(bytes);
const source = read('contracts/bhpan.source.json');
assert.equal(source.contract_sha256, crypto.createHash('sha256').update(bytes).digest('hex'));
assert.equal(source.contract_version, contract.info.version);
assert.match(source.reference_revision, /^[0-9a-f]{40}$/);
assert.equal(contract.openapi, '3.0.3');
const identifiers = new Set();
for (const [path, methods] of Object.entries(contract.paths)) {
  assert(path.startsWith('/'));
  for (const [method, operation] of Object.entries(methods)) {
    assert(['get', 'post', 'put', 'delete'].includes(method));
    assert(!identifiers.has(operation.operationId));
    identifiers.add(operation.operationId);
    assert(operation.responses['200']);
  }
}
console.log(`PASS: ${Object.keys(manifest.scenario_tests).length} adapter scenarios and ${identifiers.size} provider operations`);
