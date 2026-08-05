import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        name: "crypto",
        root: ".",
        include: ["tests/**/*.test.ts"],
        environment: "node",
        globals: false,
        testTimeout: 30_000,
        hookTimeout: 30_000,
        coverage: {
            provider: "v8",
            include: ["src/**/*.ts"],
            exclude: ["src/index.ts"],
            all: true,
            reporter: ["text", "html", "json-summary"],
            thresholds: { statements: 90, branches: 80, functions: 90, lines: 90 },
        },
    },
});
