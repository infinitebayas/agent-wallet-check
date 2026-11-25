// Static rules for code that lets an AI agent hold or move money.
// Each rule is a pattern seen in real incidents or published research (see README "Why these rules").
// Rules are heuristics: they flag code to review, they do not prove a vulnerability.

export type Level = 'error' | 'warning' | 'note';

export interface SourceFile {
  path: string; // relative, forward slashes
  text: string;
  lines: string[];
}

export interface Finding {
  ruleId: string;
  level: Level;
  path: string;
  line: number; // 1-based
  message: string;
}

export interface Rule {
  id: string;
  name: string;
  level: Level;
  summary: string;
  help: string;
  tags: string[]; // CWE / OWASP ids
  detect(file: SourceFile): Finding[];
}

// Tools or actions that move value: tool declarations (any case) and agent-framework action constants (upper case only).
const MONEY_TOOL_DECL =
  /(?:\bname|\baction|\btool|\bsimiles)\s*[:=]\s*\[?\s*["'`][\w .-]*(?:transfer|send|pay|withdraw|swap|bridge|approve|tip|grant|sweep)[\w .-]*["'`]|\bdef\s+(?:transfer|send_\w+|pay\w*|withdraw\w*|tip\w*|swap\w*)\s*\(/i;
const MONEY_ACTION_CONST = /\b(?:SEND_TOKENS?|TRANSFER(?:_TOKENS?)?|SWAP_TOKENS?|SEND_SOL|SEND_ETH)\b/;
const MONEY_TOOL = { test: (s: string): boolean => MONEY_TOOL_DECL.test(s) || MONEY_ACTION_CONST.test(s) } as RegExp;
// Evidence that limits exist somewhere in the same file.
const LIMIT_EVIDENCE =
  /max(?:imum)?_?(?:amount|value|spend|transfer|payment|tip)|spend(?:ing)?_?limit|daily_?(?:cap|limit)|per_?(?:tx|transaction)_?(?:cap|limit)|allow_?(?:list|ed_?(?:recipients|payees|addresses))|whitelist|payee_?list|budget/i;
// Places where outside text enters the agent.
const UNTRUSTED_SOURCE =
  /\b(?:tweet|mentions?|getMentions|farcaster|casts?\b|telegram|discord|message\.content|msg\.text|scrape|puppeteer|playwright|readUrl|browse|webhook|req\.body|request\.json|fetchUrl|getWebPage)\b/i;
const UNTRUSTED_HANDLING = /untrusted|sanitize|allow_?list|require(?:s)?_?(?:approval|confirmation)|human_?in_?the_?loop|owner_?signature/i;

function eachLine(file: SourceFile, re: RegExp, make: (line: string, n: number) => Finding | null): Finding[] {
  const out: Finding[] = [];
  file.lines.forEach((line, i) => {
    if (re.test(line)) {
      const f = make(line, i + 1);
      if (f) out.push(f);
    }
  });
  return out;
}

function firstLine(file: SourceFile, re: RegExp): number {
  const i = file.lines.findIndex((l) => re.test(l));
  return i < 0 ? 1 : i + 1;
}

export const RULES: Rule[] = [
  {
    id: 'AWC001',
    name: 'hardcoded-wallet-secret',
    level: 'error',
    summary: 'A private key or seed phrase is written in the code.',
    help: 'Load keys from a secrets manager or the environment at runtime, keep them out of anything the model can read, and rotate the exposed key.',
    tags: ['CWE-798', 'OWASP-LLM02'],
    detect: (f) => [
      ...eachLine(f, /(?:priv|secret|signer|wallet|pk|key)\w*\s*[:=]\s*["'`]?(?:0x)?[a-fA-F0-9]{64}\b/i, (_l, n) => ({
        ruleId: 'AWC001', level: 'error', path: f.path, line: n, message: 'Looks like a hardcoded private key.',
      })),
      ...eachLine(f, /["'`](?:[a-z]{3,8}\s+){11}[a-z]{3,8}(?:\s+[a-z]{3,8}){0,12}["'`]/, (l, n) => {
        const words = (l.match(/["'`]([a-z\s]+)["'`]/)?.[1] ?? '').trim().split(/\s+/).length;
        return words === 12 || words === 24 ? { ruleId: 'AWC001', level: 'error', path: f.path, line: n, message: `Looks like a ${words}-word seed phrase.` } : null;
      }),
    ],
  },
  {
    id: 'AWC002',
    name: 'money-tool-without-limits',
    level: 'warning',
    summary: 'A tool or action that moves funds has no visible spending cap or payee allowlist.',
    help: 'Enforce limits outside the model, in the wallet or signer: a per-transaction cap, a daily cap, an allowlist of payees and a kill switch. A limit written only in the prompt is a suggestion the model can be talked out of.',
    tags: ['CWE-770', 'OWASP-LLM06', 'OWASP-ASI02'],
    detect: (f) => (LIMIT_EVIDENCE.test(f.text) ? [] : eachLine(f, MONEY_TOOL, (_l, n) => ({
      ruleId: 'AWC002', level: 'warning', path: f.path, line: n,
      message: 'This tool can move funds, and nothing in this file caps the amount or restricts the payee.',
    }))),
  },
  {
    id: 'AWC003',
    name: 'untrusted-input-reaches-money-tool',
    level: 'warning',
    summary: 'Text from posts, messages or web pages feeds an agent that can move funds.',
    help: 'Treat outside text as data, never as instructions: separate it from the instructions, decode and normalise it (Base64, Morse, other scripts) before checking it, and require the owner\'s signed approval for payments that outside text triggers.',
    tags: ['CWE-1427', 'OWASP-LLM01', 'OWASP-ASI01'],
    detect: (f) => (MONEY_TOOL.test(f.text) && UNTRUSTED_SOURCE.test(f.text) && !UNTRUSTED_HANDLING.test(f.text)
      ? [{ ruleId: 'AWC003', level: 'warning', path: f.path, line: firstLine(f, UNTRUSTED_SOURCE),
        message: 'Outside text enters this file, which also defines a tool that moves funds, with no sign of untrusted-input handling.' }]
      : []),
  },
  {
    id: 'AWC004',
    name: 'money-as-float',
    level: 'warning',
    summary: 'An amount is handled as a floating-point number.',
    help: 'Keep amounts as integers in the token\'s smallest unit (or as a decimal library type), and convert with the token\'s real decimals. Floats round, and decimal mix-ups have sent entire balances.',
    tags: ['CWE-681', 'CWE-1339'],
    detect: (f) => eachLine(f, /\b(?:parseFloat|Number|float)\s*\(\s*[\w.$[\]'"]*(?:amount|value|price|balance|qty|quantity|lamports|wei)\b|\b(?:amount|price|value|balance)\w*\.toFixed\(/i, (_l, n) => ({
      ruleId: 'AWC004', level: 'warning', path: f.path, line: n, message: 'Amount converted to or formatted as a float.',
    })),
  },
  {
    id: 'AWC005',
    name: 'payment-without-idempotency',
    level: 'note',
    summary: 'A payment call has no idempotency key in this file.',
    help: 'Create one idempotency key per intended payment and reuse it on every retry, so a timeout cannot pay twice.',
    tags: ['CWE-837'],
    detect: (f) => (/idempoten/i.test(f.text) ? [] : eachLine(f, /\b(?:createPayment|payments\.create|paymentIntents\.create|charges\.create|transfers\.create|payouts\.create)\s*\(/, (_l, n) => ({
      ruleId: 'AWC005', level: 'note', path: f.path, line: n, message: 'Payment created without an idempotency key.',
    }))),
  },
  {
    id: 'AWC006',
    name: 'x402-autopay-without-ceiling',
    level: 'error',
    summary: 'An x402 client pays automatically with no maximum price.',
    help: 'Set a maximum payment per request (for example maxValue) and a budget per period, and pin who may be paid. A malicious or compromised API can otherwise quote any price.',
    tags: ['CWE-770', 'OWASP-ASI02'],
    detect: (f) => (/max(?:Value|Amount|Payment|Price|PaymentAmount)/.test(f.text) ? [] : eachLine(f, /\b(?:wrapFetchWithPayment|withPaymentInterceptor|createPaymentHeader)\s*\(/, (_l, n) => ({
      ruleId: 'AWC006', level: 'error', path: f.path, line: n, message: 'Automatic x402 payment without a maximum price.',
    }))),
  },
  {
    id: 'AWC007',
    name: 'unlimited-token-approval',
    level: 'error',
    summary: 'A token approval grants an unlimited allowance.',
    help: 'Approve only the amount needed for the operation, and revoke allowances when done.',
    tags: ['CWE-250', 'CWE-272'],
    detect: (f) => eachLine(f, /approve\s*\([^)]*(?:MaxUint256|MAX_UINT256|maxUint256|2\s*\*\*\s*256|0x[fF]{64}|uint256\(-1\))/, (_l, n) => ({
      ruleId: 'AWC007', level: 'error', path: f.path, line: n, message: 'Unlimited token approval.',
    })),
  },
  {
    id: 'AWC008',
    name: 'wallet-secret-in-prompt',
    level: 'error',
    summary: 'Key material is placed where the model can read it.',
    help: 'Never put keys, seed phrases or signing secrets into prompts, messages, memory or tool descriptions. The model can be made to repeat anything it can read.',
    tags: ['CWE-200', 'OWASP-LLM02', 'OWASP-LLM07'],
    detect: (f) => eachLine(f, /(?:PRIVATE_KEY|MNEMONIC|SEED_PHRASE|privateKey|secretKey|mnemonic)/, (l, n) =>
      /(?:prompt|system|messages|instructions|content\s*:|memory|description\s*:)/i.test(l)
        ? { ruleId: 'AWC008', level: 'error', path: f.path, line: n, message: 'Key material on the same line as prompt or message content.' }
        : null),
  },
];
