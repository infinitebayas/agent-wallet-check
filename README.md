# agent-wallet-check

Static checks for AI agents that hold a wallet or make payments.

It reads your source code (TypeScript, JavaScript, Python) and flags patterns behind real agent losses: hardcoded keys, money tools with no spending limits, outside text that reaches a payment tool, float amounts, and x402 auto-pay with no price ceiling.

- No runtime dependencies, no network calls, no telemetry. It reads files and prints a report.
- Output as text, JSON or SARIF 2.1.0 (GitHub code scanning).
- MIT licence.

## Use

```bash
npx github:infinitebayas/agent-wallet-check ./path/to/agent
```

```text
src/agent.ts:4   error    AWC001  Looks like a hardcoded private key.
src/agent.ts:10  warning  AWC002  This tool can move funds, and nothing in this file caps the amount or restricts the payee.
src/agent.ts:26  error    AWC006  Automatic x402 payment without a maximum price.
```

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `[path]` | `.` | Folder or file to scan |
| `--format text\|json\|sarif` | `text` | Report format |
| `--output <file>` | stdout | Write the report to a file |
| `--fail-on error\|warning\|note\|none` | `error` | Exit with code 1 when a finding at this level or worse exists |
| `--rules` | | List the rules |

Exit codes: `0` no failing findings, `1` failing findings, `2` bad arguments or path.

It skips `node_modules`, `dist`, `build`, virtual environments, hidden folders, minified files and files over 1 MB.

### GitHub Actions

```yaml
name: agent-wallet-check
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: infinitebayas/agent-wallet-check@v0.1.0
        with:
          path: .
          format: sarif
          output: agent-wallet-check.sarif
          fail-on: none
      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: agent-wallet-check.sarif
```

Findings then appear under the repository's **Security → Code scanning**. Use `fail-on: error` to block merges instead.

### Silencing a reviewed finding

Put `awc-ignore` and the rule ID on the line or the line above, with your reason:

```ts
// awc-ignore AWC004 display only, never used as a machine value
const shown = parseFloat(balance.amount);
```

## Rules

Every rule maps to incidents or research in the attack library behind [inspect.infinitebayas.com](https://inspect.infinitebayas.com). The sources are public.

### AWC001

**hardcoded-wallet-secret** (error). A 64-hex private key or a 12/24-word seed phrase in the code. Anything in the repository can leak through history, logs, CI or the model itself. Malicious agent "skills" have been caught stealing exactly these ([The Hacker News, Feb 2026](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html)).
Fix: load keys at runtime from a secrets manager or the environment, keep them away from anything the model reads, and rotate any key that was committed.

### AWC002

**money-tool-without-limits** (warning). A tool or action that can transfer, send, pay, swap, withdraw, approve or tip, in a file with no visible cap or payee allowlist. Agents have been talked into paying out their whole balance ([Freysa, The Block](https://www.theblock.co/post/328747/human-player-outwits-freysa-ai-agent-in-47000-crypto-challenge); [Lobstar Wilde, CoinDesk](https://www.coindesk.com/markets/2026/02/23/ai-bot-s-tipping-blunder-hands-usd250-000-memecoin-pile-to-x-sad-story-poster)).
Fix: enforce a per-transaction cap, a daily cap, a payee allowlist and a kill switch in code or in the wallet, not in the prompt. A limit that lives only in the prompt is a suggestion.

### AWC003

**untrusted-input-reaches-money-tool** (warning). Posts, mentions, chat messages, scraped pages or webhooks enter a file that also defines a money tool, with no sign of untrusted-input handling. An X post with a Morse-encoded instruction moved about $150k from an agent wallet ([Giskard](https://giskard.ai/knowledge/how-grok-got-prompt-injected-an-x-user-drained-150-000-from-an-ai-wallet); [OECD AI incident](https://oecd.ai/en/incidents/2026-05-04-4a73)). Planted "memories" made agents send crypto ([arXiv 2503.16248](https://arxiv.org/html/2503.16248v1)).
Fix: treat outside text as data, never instructions. Decode and normalise it (Base64, Morse, other scripts) before any check, and require the owner's signed approval for payments that outside text triggers.

### AWC004

**money-as-float** (warning). `parseFloat`, `Number()` or `float()` on an amount, or `.toFixed()` on one. Floats round, and unit mix-ups have sent whole holdings ([The Block, Lobstar Wilde](https://www.theblock.co/post/390722/ai-agent-created-by-openai-dev-accidentally-sends-entire-memecoin-holdings-to-reply-guy)).
Fix: integers in the token's smallest unit (`bigint`) or a decimal type, converted with the token's real decimals.

### AWC005

**payment-without-idempotency** (note). A payment API call in a file with no idempotency key. A retry after a timeout can pay twice.
Fix: create one key per intended payment and reuse it on every retry.

### AWC006

**x402-autopay-without-ceiling** (error). `wrapFetchWithPayment`, `withPaymentInterceptor` or `createPaymentHeader` with no maximum price in the file. The client signs whatever the server quotes ([CSA research note on x402 SDK flaws](https://labs.cloudsecurityalliance.org/research/csa-research-note-x402-agent-payment-sdk-flaws-20261026-csa/); [GHSA-qr2g-p6q7-w82m](https://github.com/advisories/GHSA-qr2g-p6q7-w82m); [arXiv 2605.11781](https://arxiv.org/abs/2605.11781)).
Fix: set a maximum per request, a budget per period and the payees you accept.

### AWC007

**unlimited-token-approval** (error). `approve(spender, MaxUint256)` or the equivalent. One compromised or malicious spender can then take the full balance, now or later ([AgentKit approvals brief](https://feed.craftedsignal.io/briefs/2026-04-coinbase-agentkit-prompt-injection/)).
Fix: approve only what the operation needs, and revoke afterwards.

### AWC008

**wallet-secret-in-prompt** (error). Key material on the same line as a prompt, system message, memory, instructions or tool description. A model can be made to repeat anything it can read, and malicious LLM routers have been shown to harvest it ([arXiv 2604.08407](https://arxiv.org/pdf/2604.08407)).
Fix: the model never sees keys. Signing happens in code the model cannot reach.

## Limits (read this)

- These are pattern checks on single files. They miss limits defined in another file and flag code that is safe for reasons they cannot see. Treat every finding as "review this", not "this is exploitable".
- A clean run does not mean an agent is safe. Most agent losses come from behaviour under attack (what the model does with a hostile post), which no static check can see.
- Behaviour testing means attacking a copy of the agent with fake money. That is what an inspection does: [inspect.infinitebayas.com](https://inspect.infinitebayas.com). You can see weak demo agents attacked with brakes off and on at [/lab](https://inspect.infinitebayas.com/lab).

## Develop

```bash
npm install
npm test        # builds dist/ and runs node --test
```

`dist/` is committed so `npx github:…` works without a build step. Rebuild it before committing changes to `src/`.

New rules need a fixture in `test/fixtures/bad`, a clean counterpart in `test/fixtures/good`, and a public source in this README.

## Licence

MIT. See [LICENSE](LICENSE).
