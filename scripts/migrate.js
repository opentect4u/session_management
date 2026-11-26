/** Applies db/postgres/schema.sql (idempotent). Usage: npm run db:migrate (needs PG_* env vars). */
const fs = require("node:fs");
const path = require("node:path");
const { pool } = require("../config/db");

(async () => {
  const sql = fs.readFileSync(path.join(__dirname, "..", "db", "postgres", "schema.sql"), "utf8");
  await pool.query(sql);
  console.log("schema applied (auth.*)");
  await pool.end();
})().catch((err) => { console.error("migration failed:", err.message); process.exit(1); });
