const config = require("./config");
const app = require("./app");
const { pool } = require("./config/db");
const { startSessionCleanup } = require("./jobs/sessionCleanup");

const server = app.listen(config.server.port, () => {
  console.log(`API listening on port ${config.server.port} (${config.env})`);
  startSessionCleanup();
});

server.keepAliveTimeout = config.server.keepAliveTimeoutMs;
server.headersTimeout = config.server.keepAliveTimeoutMs + 5000; // must exceed keepAliveTimeout

const shutdown = () => server.close(() => pool.end().then(() => process.exit(0)));
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
