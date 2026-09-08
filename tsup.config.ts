import { defineConfig } from "tsup";

export default defineConfig([
  // ── Main SDK (ESM + CJS, peer deps external) ──────────────────────────────
  {
    entry:     ["src/index.ts"],
    outDir:    "dist",
    format:    ["esm", "cjs"],
    dts:       true,
    splitting: false,
    sourcemap: true,
    clean:     true,
    treeshake: true,
    target:    "node18",
    external:  ["express", "fastify"],
  },
  // ── CLI binary (bundled standalone — secretlint included) ─────────────────
  {
    entry:      { cli: "src/cli.ts" },
    outDir:     "dist",
    format:     ["cjs"],
    dts:        false,
    splitting:  false,
    sourcemap:  false,
    treeshake:  true,
    target:     "node18",
    noExternal: ["@secretlint/core", "@secretlint/secretlint-rule-preset-recommend"],
    external:   ["express", "fastify"],
  },
]);
