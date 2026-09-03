import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  // db/index.ts applies Drizzle migrations at startup by reading
  // src/db/migrations from disk — include it in the standalone output.
  // Controls JSONs are read at runtime via load-controls.ts (dynamic fs
  // reads not statically traceable) — include them explicitly so the
  // runner has registry.json / frameworks / risk-severity.
  outputFileTracingIncludes: {
    "/**": ["./src/db/migrations/**", "../src/M365-Assess/controls/**"],
  },
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          // vr is deprecated and triggers browser console warnings — omit it
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()" },
        ],
      },
    ];
  },
};

export default nextConfig;
