import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Mirror the app's tsconfig path alias so tests can import modules that use
// "@/..." internally (e.g. lib/graph/disconnect.ts importing the db singleton).
export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
