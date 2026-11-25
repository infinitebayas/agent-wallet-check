import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep, extname } from 'node:path';
import { RULES, type Finding, type SourceFile } from './rules.js';

const EXTENSIONS = new Set(['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs', '.py']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'coverage', 'vendor', 'venv', '.venv', '__pycache__', '.next', '.turbo']);
const MAX_BYTES = 1_000_000;

/** Lists the source files under root (skips dependencies, build output, minified and very large files). */
export function listFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      const st = statSync(full, { throwIfNoEntry: false });
      if (!st || st.isSymbolicLink()) continue;
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name) && !name.startsWith('.')) walk(full);
      } else if (EXTENSIONS.has(extname(name)) && !name.endsWith('.min.js') && st.size <= MAX_BYTES) {
        out.push(full);
      }
    }
  };
  const st = statSync(root);
  st.isDirectory() ? walk(root) : out.push(root);
  return out.sort();
}

/** `// awc-ignore AWC002` (or `# awc-ignore AWC002`) on the line or the line above suppresses that rule there. */
function suppressed(lines: string[], f: Finding): boolean {
  const re = new RegExp(`awc-ignore\\b[^\\n]*\\b${f.ruleId}\\b`);
  return re.test(lines[f.line - 1] ?? '') || re.test(lines[f.line - 2] ?? '');
}

export function scan(root: string): Finding[] {
  const findings: Finding[] = [];
  const base = statSync(root).isDirectory() ? root : join(root, '..');
  for (const full of listFiles(root)) {
    const text = readFileSync(full, 'utf8');
    const file: SourceFile = { path: relative(base, full).split(sep).join('/'), text, lines: text.split(/\r?\n/) };
    for (const rule of RULES) {
      for (const f of rule.detect(file)) {
        if (!suppressed(file.lines, f)) findings.push(f);
      }
    }
  }
  return findings.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line || a.ruleId.localeCompare(b.ruleId));
}
