import { RULES, type Finding, type Level } from './rules.js';

export const VERSION = '0.1.0';
const REPO = 'https://github.com/infinitebayas/agent-wallet-check';

/** SARIF 2.1.0 (OASIS), readable by GitHub code scanning. */
export function toSarif(findings: Finding[]): object {
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'agent-wallet-check',
          version: VERSION,
          informationUri: REPO,
          rules: RULES.map((r) => ({
            id: r.id,
            name: r.name,
            shortDescription: { text: r.summary },
            fullDescription: { text: r.summary },
            help: { text: r.help },
            helpUri: `${REPO}#${r.id.toLowerCase()}`,
            defaultConfiguration: { level: r.level },
            properties: { tags: ['security', ...r.tags] },
          })),
        },
      },
      results: findings.map((f) => ({
        ruleId: f.ruleId,
        ruleIndex: RULES.findIndex((r) => r.id === f.ruleId),
        level: f.level,
        message: { text: f.message },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.path }, region: { startLine: f.line } } }],
      })),
    }],
  };
}

export function toJson(findings: Finding[]): object {
  return { tool: 'agent-wallet-check', version: VERSION, findings, counts: counts(findings) };
}

export function counts(findings: Finding[]): Record<Level, number> {
  const c: Record<Level, number> = { error: 0, warning: 0, note: 0 };
  for (const f of findings) c[f.level]++;
  return c;
}

export function toText(findings: Finding[]): string {
  if (findings.length === 0) return 'agent-wallet-check: no findings. (Static checks only; this is not a security inspection.)\n';
  const lines = findings.map((f) => `${f.path}:${f.line}  ${f.level.padEnd(7)} ${f.ruleId}  ${f.message}`);
  const c = counts(findings);
  return `${lines.join('\n')}\n\n${findings.length} finding(s): ${c.error} error, ${c.warning} warning, ${c.note} note.\nRule help: ${REPO}#rules\n`;
}
