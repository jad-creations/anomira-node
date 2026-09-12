# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Open-source project files: license, contributing guide, code of conduct,
  security policy, issue/PR templates, CI, Dependabot, and example apps.
- Example apps run against a local mock ingest so contributors do not need
  Anomira dashboard credentials.

## [0.2.7] - 2025-05-17

### Added

- Drop-in Express and Fastify middleware for API security monitoring.
- Automatic capture of request method, path, status, IP, geolocation, and latency.
- Detectors for brute force, rate abuse, path traversal, XSS, scanner probing,
  geo-velocity, SSRF, and JWT manipulation.
- Manual `track`, `trackLogin`, and `trackPhoneAuth` helpers.
- Structured logging via `anomira.log` and optional `captureConsole`.
- Blocklist and firewall-rule sync from the Anomira dashboard.
- Shadow endpoint detection via `declareEndpoints`.
- `anomira` CLI secret scanner (`npx @anomira/node-sdk scan`).
- Dual ESM / CommonJS publish with TypeScript types.

[Unreleased]: https://github.com/jad-creations/anomira-node/compare/v0.2.7...HEAD
[0.2.7]: https://github.com/jad-creations/anomira-node/releases/tag/v0.2.7
