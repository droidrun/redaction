# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on https://github.com/droidrun/redaction. Do not open a public issue or pull
request for a vulnerability.

Relevant reports include text or JSON input that makes any implementation (TypeScript, Python, Go) return a secret
it should have replaced, input that makes redaction take super-linear time, and differences between the three
implementations that leak. Please include the input, the entry point and mode used, and the output you saw.

You get an answer within a few working days. Fixes are released for the newest version.

## Scope notes

The secrets in test vectors, corpora and fixtures (`spec/vectors/`, `spec/corpus/`, `**/*.test.ts` and similar) are
synthetic; they are not credentials.
