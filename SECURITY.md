# Security policy

## Reporting a problem in this tool

Email **inspect@infinitebayas.com** with "agent-wallet-check" in the subject. Please do not open a public issue for a security problem. We reply within 5 working days.

Useful details: version (`agent-wallet-check --version`), the input that triggers the problem (a minimal file, with any real keys removed), and what you expected.

## What the tool does and does not do

- It reads files under the path you give it and writes a report. It makes no network calls and has no runtime dependencies.
- It does not run, import or evaluate the code it scans.
- It prints file paths, line numbers and rule messages, never the matched text, so a found key is not copied into logs or SARIF files.

## Supported versions

Only the latest release receives fixes.
