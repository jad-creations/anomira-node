# Contributing to @anomira/node-sdk

Thanks for helping improve the Anomira Node.js SDK. This document is the
shortest path from clone to a reviewable pull request.

## Code of conduct

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Report unacceptable behavior to [sdk@anomira.io](mailto:sdk@anomira.io).

## Security issues

Do not open a public issue or pull request for a vulnerability. Follow
[SECURITY.md](SECURITY.md) instead.

## Prerequisites

- Node.js 18 or later (20 is what CI uses as the primary version)
- npm 9 or later

## Local setup

```bash
git clone https://github.com/jad-creations/anomira-node.git
cd anomira-node
npm install
```

Tests and examples do **not** need Anomira credentials. This repository is the
SDK only; the Anomira dashboard is not open source, so contributors cannot
create API keys. The example apps start a local mock ingest automatically.

## Checks to run before you open a PR

```bash
npm run typecheck
npm test
npm run lint
npm run build
```

To try middleware against a real Express or Fastify app after a build:

```bash
npm run build
cd examples/express   # or examples/fastify
npm install
npm start
```

Hit `/api/health` or `/api/auth/login` and watch `[mock-ingest]` lines in the
terminal. Use `npm test` / `npm run test:watch` for detector behavior.

## Project layout

| Path | What it is |
| --- | --- |
| `src/` | SDK source |
| `src/middleware/` | Express and Fastify adapters |
| `src/__tests__/` | Vitest suites |
| `src/cli.ts` | `anomira` secret-scanner CLI |
| `examples/` | Express/Fastify demos plus a local mock ingest (no Anomira account) |
| `dist/` | Build output (do not edit or commit) |

## Pull requests

1. Open an issue first for larger changes so we can agree on the approach.
2. Create a branch from `main`.
3. Keep the change focused. Prefer small PRs over mixed refactors.
4. Add or update tests in `src/__tests__/` for behavior changes.
5. Update `README.md` and `CHANGELOG.md` (`[Unreleased]`) when the public API or
   user-facing behavior changes.
6. Never commit secrets, API keys, `.env` files, or `dist/`.
7. Fill in the pull request template.

### Commit messages

Use a short imperative subject, for example:

- `Add Fastify onClose flush example`
- `Fix geo-velocity skip when geoLookupUrl is unset`
- `Document trusted npm publishing`

## Coding notes

- TypeScript, ESM source, compiled to ESM and CommonJS via `tsup`.
- `express` and `fastify` are optional peer dependencies — keep them out of the
  published SDK runtime bundle.
- Prefer existing patterns in `src/client.ts` and the middleware adapters over
  new abstractions.
- Public exports live in `src/index.ts`. Treat anything not exported from there
  as internal.

## Release process (maintainers)

1. Update `CHANGELOG.md` and `package.json` version.
2. Tag `vX.Y.Z` after merging to `main`.
3. The [release workflow](.github/workflows/release.yml) builds and publishes
   `@anomira/node-sdk` to npm with provenance.

Configure [npm trusted publishing](https://docs.npmjs.com/trusted-publishers)
for this GitHub repository before the first automated publish.

## Questions

Open a GitHub Discussion or issue, or email [sdk@anomira.io](mailto:sdk@anomira.io).
