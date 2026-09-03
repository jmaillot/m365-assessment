import "dotenv/config";
import { defineConfig } from "drizzle-kit";

// Local dev default; Docker sets DATABASE_PATH=/app/data/m365-assess.db.
export default defineConfig({
  dialect: "sqlite",
  schema: "./src/db/schema.ts",
  out: "./src/db/migrations",
  dbCredentials: {
    url: process.env.DATABASE_PATH ?? "./data/m365-assess.db",
  },
});
