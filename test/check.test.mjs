import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan } from '../dist/scan.js';
import { toSarif } from '../dist/report.js';
import { RULES } from '../dist/rules.js';

const here = dirname(fileURLToPath(import.meta.url));
const fx = (name) => join(here, 'fixtures', name);
const cli = join(here, '..', 'dist', 'cli.js');
const ids = (findings) => [...new Set(findings.map((f) => f.ruleId))].sort();

test('every rule fires on the unsafe fixtures', () => {
  assert.deepEqual(ids(scan(fx('bad'))), RULES.map((r) => r.id).sort());
});

test('python files are scanned', () => {
  const py = scan(fx('bad')).filter((f) => f.path === 'agent.py');
  assert.deepEqual(ids(py), ['AWC002', 'AWC004']);
});

test('the safe fixture has no findings', () => {
  assert.deepEqual(scan(fx('good')), []);
});

test('awc-ignore suppresses the named rule', () => {
  assert.deepEqual(scan(fx('suppressed')), []);
});

test('findings point at the right line', () => {
  const key = scan(fx('bad')).find((f) => f.ruleId === 'AWC001' && f.path === 'agent.ts');
  assert.equal(key.line, 4);
});

test('SARIF output has the 2.1.0 shape', () => {
  const s = toSarif(scan(fx('bad')));
  assert.equal(s.version, '2.1.0');
  assert.equal(s.runs[0].tool.driver.rules.length, RULES.length);
  for (const r of s.runs[0].results) {
    assert.ok(r.ruleIndex >= 0);
    assert.ok(r.locations[0].physicalLocation.region.startLine >= 1);
  }
});

test('CLI exit codes follow --fail-on', () => {
  const run = (...a) => spawnSync(process.execPath, [cli, ...a], { encoding: 'utf8' });
  assert.equal(run(fx('bad')).status, 1);
  assert.equal(run(fx('bad'), '--fail-on', 'none').status, 0);
  assert.equal(run(fx('good')).status, 0);
  assert.equal(run(fx('missing')).status, 2);
  assert.equal(run(fx('bad'), '--format', 'xml').status, 2);
  const json = JSON.parse(run(fx('bad'), '--format', 'json', '--fail-on', 'none').stdout);
  assert.ok(json.counts.error > 0);
});
