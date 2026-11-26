const { Pool } = require("pg");
const config = require("./index");

/** The connection pool. Only models/MasterModule.js (and the scripts) use it directly. */
const pool = new Pool({
  host: config.db.host,
  port: config.db.port,
  user: config.db.user,
  password: config.db.password,
  database: config.db.database,
  ssl: config.db.ssl ? { rejectUnauthorized: false } : false,
  max: config.db.poolMax,
});

pool.on("error", (err) => console.error("[db] idle client error:", err.message));

module.exports = { pool };
