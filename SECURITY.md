# Security Policy

Anomira is a security product. Please report vulnerabilities privately so we can
fix them before they are public.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Use one of these private channels:

1. **GitHub Security Advisories** — [Report a vulnerability](https://github.com/jad-creations/anomira-node/security/advisories/new)
2. **Email** — [sdk@anomira.io](mailto:sdk@anomira.io) with the subject `Security report: @anomira/node-sdk`

Include as much of the following as you can:

- Affected package version and Node.js version
- A clear description of the issue and its impact
- Steps to reproduce, or a minimal proof of concept
- Any suggested fix, if you have one

## What to expect

- We will acknowledge receipt within **3 business days**.
- We will send a status update within **7 days**, and keep you informed as we investigate.
- We aim to ship a fix for confirmed issues within **90 days**, sooner when the impact is high.
- We will credit you in the advisory if you want to be named.

## Scope

**In scope**

- Secret leakage from the SDK or CLI scanner
- Bypass of request instrumentation, blocklist, or firewall matching
- Remote code execution, injection, or prototype pollution in this repository
- Supply-chain issues in the published npm package (`@anomira/node-sdk`)

**Out of scope**

- Vulnerabilities that require a stolen `ANOMIRA_API_KEY`
- Issues in Express, Fastify, or other peer dependencies (report those upstream)
- Denial of service against `api.anomira.io` / `ingest.anomira.io`
- Social engineering, physical attacks, or reports with no realistic exploit path

## Disclosure

Please give us time to release a fix before sharing details publicly. We will
coordinate a disclosure date with you once a patched version is on npm.
