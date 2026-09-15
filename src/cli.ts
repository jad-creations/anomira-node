#!/usr/bin/env node
/**
 * Anomira Pre-Production Secret Scanner
 * ──────────────────────────────────────
 * Usage:  npx @anomira/node-sdk scan [path] [options]
 *
 * Detection layers:
 *   1. secretlint — 50+ service-specific rules (AWS, GCP, GitHub, Stripe, Slack…)
 *   2. Custom regex — Nigerian PII (BVN/NIN), card PANs, connection strings
 *   3. Entropy analysis (--strict) — catches unknown high-entropy secrets
 *
 * Exit codes:
 *   0 — no violations found
 *   1 — one or more violations found (CI/CD compatible)
 */

import fs   from "node:fs";
import path from "node:path";
import { lintSource }            from "@secretlint/core";
import { creator as presetCreator } from "@secretlint/secretlint-rule-preset-recommend";
import { scanForLeaks, redactMessage } from "./sensitive.js";

// ─── ANSI colours ────────────────────────────────────────────────────────────

const isTTY = process.stdout.isTTY;
const c = {
  reset:  isTTY ? "\x1b[0m"  : "",
  bold:   isTTY ? "\x1b[1m"  : "",
  dim:    isTTY ? "\x1b[2m"  : "",
  red:    isTTY ? "\x1b[31m" : "",
  yellow: isTTY ? "\x1b[33m" : "",
  green:  isTTY ? "\x1b[32m" : "",
  cyan:   isTTY ? "\x1b[36m" : "",
  grey:   isTTY ? "\x1b[90m" : "",
};

// ─── File scanning config ────────────────────────────────────────────────────

const SCAN_EXTS = new Set([
  ".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx",
  ".py", ".rb", ".go", ".java", ".php", ".cs", ".rs",
  ".env", ".env.local", ".env.example", ".env.test", ".env.production",
  ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".config",
  ".sh", ".bash", ".zsh", ".fish",
  ".tf", ".tfvars",   // Terraform
  ".pem", ".key",     // certificate/key files
]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", "dist", "build", "out",
  "coverage", "__pycache__", ".venv", "venv", ".env",
  ".turbo", ".cache", "tmp", "temp",
  // Test directories — skipped by default, use --include-tests to scan them
  "tests", "test", "__tests__", "spec", "__spec__", "fixtures", "__fixtures__", "mocks", "__mocks__",
]);

// Test file suffixes — skipped by default
const TEST_FILE_PATTERNS = [
  ".test.js", ".test.ts", ".test.jsx", ".test.tsx",
  ".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx",
];

// ─── Entropy analysis ─────────────────────────────────────────────────────────

function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const ch of str) freq[ch] = (freq[ch] ?? 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, count) => {
    const p = count / len;
    return sum + p * Math.log2(p);
  }, 0);
}

// Looks for high-entropy strings assigned to secret-like variable names.
// Returns the value and entropy if suspicious.
function findHighEntropySecrets(line: string): { value: string; entropy: number } | null {
  // Match any variable name containing a secret-like keyword (camelCase, snake_case, etc.)
  // e.g. internalToken, webhookSecret, API_KEY, authCredential
  const assignmentMatch = line.match(
    /\b\w*(?:key|token|secret|password|passwd|pwd|auth|credential|api)\w*\s*[:=]\s*["']?([A-Za-z0-9+/=_\-.]{20,})["']?/i
  );
  if (!assignmentMatch) return null;

  const value   = assignmentMatch[1]!;
  const entropy = shannonEntropy(value);

  // Thresholds tuned to reduce false positives on common values like UUIDs
  // Base64-like: entropy > 4.5, hex-like: entropy > 3.5
  const isBase64Like = /^[A-Za-z0-9+/=]{20,}$/.test(value);
  const isHexLike    = /^[0-9a-fA-F]{20,}$/.test(value);
  const threshold    = isHexLike ? 3.5 : isBase64Like ? 4.5 : 4.0;

  if (entropy >= threshold) return { value, entropy };
  return null;
}

function redactExcerpt(line: string): string {
  return redactMessage(line.trim()).slice(0, 120);
}

interface Violation {
  file:    string;
  line:    number;
  col?:    number;
  type:    string;
  label:   string;
  excerpt: string;
  source:  "secretlint" | "custom" | "entropy";
}

// ─── secretlint config ───────────────────────────────────────────────────────

const SECRETLINT_CONFIG = {
  rules: [
    {
      id:      "@secretlint/secretlint-rule-preset-recommend",
      rule:    presetCreator,
      options: {},
    },
  ],
};

// ─── Scanning functions ──────────────────────────────────────────────────────

function isTestFile(filePath: string): boolean {
  const base = path.basename(filePath);
  return TEST_FILE_PATTERNS.some((p) => base.endsWith(p));
}

function shouldScan(filePath: string, includeTests: boolean): boolean {
  if (!includeTests && isTestFile(filePath)) return false;
  const ext  = path.extname(filePath);
  const base = path.basename(filePath);
  if (base.startsWith(".env")) return true;
  if (ext === ".pem" || ext === ".key") return true;
  return SCAN_EXTS.has(ext);
}

async function scanFile(filePath: string, strict: boolean): Promise<Violation[]> {
  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch {
    return [];
  }

  const violations: Violation[] = [];

  // ── Layer 1: secretlint (50+ service-specific rules) ─────────────────────
  try {
    const result = await lintSource({
      source: {
        content,
        filePath,
        contentType: "text",
      },
      options: {
        config: SECRETLINT_CONFIG,
      },
    });

    for (const msg of result.messages) {
      const lineNum = msg.loc?.start?.line ?? 1;
      const lineText = content.split("\n")[lineNum - 1] ?? "";
      violations.push({
        file:    filePath,
        line:    lineNum,
        col:     msg.loc?.start?.column,
        type:    msg.ruleId,
        label:   msg.message,
        excerpt: redactExcerpt(lineText),
        source:  "secretlint",
      });
    }
  } catch { /* secretlint may not support all file types */ }

  // ── Layer 2: custom patterns (Nigerian PII, card PANs, DB strings) ────────
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line    = lines[i]!;
    const matches = scanForLeaks(line);
    for (const match of matches) {
      // Avoid duplicating what secretlint already caught on this line
      const alreadyCaught = violations.some(
        (v) => v.line === i + 1 && v.source === "secretlint"
      );
      if (!alreadyCaught) {
        violations.push({
          file:    filePath,
          line:    i + 1,
          type:    match.type,
          label:   match.label,
          excerpt: redactExcerpt(line),
          source:  "custom",
        });
      }
    }
  }

  // ── Layer 3: entropy analysis (--strict only) ─────────────────────────────
  if (strict) {
    for (let i = 0; i < lines.length; i++) {
      const hit = findHighEntropySecrets(lines[i]!);
      if (hit) {
        const alreadyCaught = violations.some((v) => v.line === i + 1);
        if (!alreadyCaught) {
          violations.push({
            file:    filePath,
            line:    i + 1,
            type:    "high_entropy",
            label:   `High-entropy secret (entropy: ${hit.entropy.toFixed(2)})`,
            excerpt: redactExcerpt(lines[i]!),
            source:  "entropy",
          });
        }
      }
    }
  }

  return violations;
}

function* walkDir(dir: string, includeTests: boolean): Generator<string> {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkDir(full, includeTests);
    } else if (entry.isFile() && shouldScan(full, includeTests)) {
      yield full;
    }
  }
}

// ─── CLI entry ───────────────────────────────────────────────────────────────

async function main() {
  const args       = process.argv.slice(2);
  const positional = args.filter((a) => !a.startsWith("--") && a !== "scan");
  const scanPath   = positional[0] ?? ".";
  const quiet        = args.includes("--quiet") || args.includes("-q");
  const jsonOut      = args.includes("--json");
  const strict       = args.includes("--strict");
  const includeTests = args.includes("--include-tests");

  if (args.includes("--help") || args.includes("-h") || args[0] === "help") {
    console.log(`
${c.bold}Anomira Secret Scanner${c.reset}

Usage: npx @anomira/node-sdk scan [path] [options]
   or: anomira scan [path]          (if installed in project)

Detection layers:
  Layer 1  secretlint — 50+ rules: AWS, GCP, GitHub, Stripe, Slack, Twilio…
  Layer 2  Custom     — Nigerian BVN/NIN, card PANs, DB connection strings
  Layer 3  Entropy    — High-entropy string detection (--strict only)

Options:
  --strict           Enable entropy analysis (catches unknown secrets, more noise)
  --include-tests    Also scan test files (*.test.*, *.spec.*, tests/ dirs — skipped by default)
  --quiet, -q        Only print violations (suppress summary header)
  --json             Machine-readable JSON output (for CI pipelines)
  --help, -h         Show this help

Examples:
  npx @anomira/node-sdk scan ./src
  npx @anomira/node-sdk scan . --strict
  npx @anomira/node-sdk scan ./src --json
  anomira scan ./backend --quiet

Exit codes: 0 = clean  1 = violations found
`.trim());
    process.exit(0);
  }

  const target = path.resolve(scanPath);
  if (!fs.existsSync(target)) {
    console.error(`${c.red}Error:${c.reset} Path not found: ${target}`);
    process.exit(1);
  }

  if (!quiet && !jsonOut) {
    console.log(`\n${c.bold}${c.cyan}Anomira Secret Scanner${c.reset}`);
    console.log(`${c.grey}Target:  ${target}${c.reset}`);
    console.log(`${c.grey}Layers:  secretlint + custom patterns${strict ? " + entropy" : ""}${c.reset}\n`);
  }

  const files = fs.statSync(target).isDirectory() ? [...walkDir(target, includeTests)] : [target];
  const allViolations: Violation[] = [];
  let fileCount = 0;

  for (const file of files) {
    fileCount++;
    const violations = await scanFile(file, strict);
    allViolations.push(...violations);

    if (!jsonOut && violations.length > 0) {
      const rel = path.relative(process.cwd(), file);
      console.log(`${c.bold}${c.red}FAIL${c.reset} ${rel}`);
      for (const v of violations) {
        const sourceTag = v.source === "secretlint" ? `${c.cyan}[secretlint]${c.reset}` :
                          v.source === "entropy"    ? `${c.yellow}[entropy]${c.reset}` :
                                                      `${c.grey}[custom]${c.reset}`;
        console.log(`  ${c.yellow}Line ${v.line}${c.reset} ${sourceTag} ${c.bold}${v.label}${c.reset}`);
        console.log(`  ${c.grey}${v.excerpt}${c.reset}`);
      }
      console.log();
    }
  }

  if (jsonOut) {
    console.log(JSON.stringify({
      files:      fileCount,
      violations: allViolations.length,
      strict,
      results:    allViolations.map((v) => ({
        file:    path.relative(process.cwd(), v.file),
        line:    v.line,
        type:    v.type,
        label:   v.label,
        source:  v.source,
        excerpt: v.excerpt,
      })),
    }, null, 2));
    process.exit(allViolations.length > 0 ? 1 : 0);
  }

  if (allViolations.length === 0) {
    if (!quiet) {
      console.log(`${c.green}${c.bold}✓ No secrets found${c.reset} ${c.grey}(${fileCount} files scanned)${c.reset}\n`);
    }
    process.exit(0);
  }

  const bySource = allViolations.reduce<Record<string, number>>((acc, v) => {
    acc[v.source] = (acc[v.source] ?? 0) + 1;
    return acc;
  }, {});

  if (!quiet) {
    console.log(
      `${c.red}${c.bold}✗ ${allViolations.length} secret(s) found${c.reset} ` +
      `${c.grey}in ${fileCount} files — ` +
      Object.entries(bySource).map(([s, n]) => `${s}: ${n}`).join(", ") +
      `${c.reset}\n`
    );
  }
  process.exit(1);
}

main().catch((err: unknown) => {
  console.error(`${isTTY ? "\x1b[31m" : ""}Scanner error:${isTTY ? "\x1b[0m" : ""}`, err);
  process.exit(1);
});
