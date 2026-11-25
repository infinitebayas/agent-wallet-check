#!/usr/bin/env node
import { writeFileSync, existsSync } from 'node:fs';
import { scan } from './scan.js';
import { toJson, toSarif, toText, VERSION } from './report.js';
import { RULES, type Level } from './rules.js';

const USAGE = `agent-wallet-check ${VERSION}: static checks for AI agents that hold wallets or move money

Usage: agent-wallet-check [path] [--format text|json|sarif] [--output file] [--fail-on error|warning|note|none]
       agent-wallet-check --rules

  path        folder or file to scan (default: current folder)
  --format    output format (default: text)
  --output    write the report to a file instead of stdout
  --fail-on   exit with code 1 when a finding of this level or worse exists (default: error)
  --rules     list the rules
`;

function arg(name: string, fallback: string, argv: string[]): string {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
}

export function main(argv: string[]): number {
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (argv.includes('--version')) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (argv.includes('--rules')) {
    for (const r of RULES) process.stdout.write(`${r.id}  ${r.level.padEnd(7)} ${r.name}: ${r.summary}\n`);
    return 0;
  }
  const flags = new Set(['--format', '--output', '--fail-on']);
  const path = argv.find((a, i) => !a.startsWith('--') && !flags.has(argv[i - 1] ?? '')) ?? '.';
  const format = arg('format', 'text', argv);
  const failOn = arg('fail-on', 'error', argv);
  if (!['text', 'json', 'sarif'].includes(format) || !['error', 'warning', 'note', 'none'].includes(failOn)) {
    process.stderr.write(USAGE);
    return 2;
  }
  if (!existsSync(path)) {
    process.stderr.write(`agent-wallet-check: path not found: ${path}\n`);
    return 2;
  }
  const findings = scan(path);
  const out = format === 'sarif' ? JSON.stringify(toSarif(findings), null, 2) + '\n'
    : format === 'json' ? JSON.stringify(toJson(findings), null, 2) + '\n'
    : toText(findings);
  const output = arg('output', '', argv);
  output ? writeFileSync(output, out) : process.stdout.write(out);
  const order: Level[] = ['error', 'warning', 'note'];
  if (failOn === 'none') return 0;
  const threshold = order.indexOf(failOn as Level);
  return findings.some((f) => order.indexOf(f.level) <= threshold) ? 1 : 0;
}

process.exitCode = main(process.argv.slice(2));
