const config = require("../config");
const { AppError } = require("../utils/errors");
const { fail } = require("../utils/response");

const notFound = (req, res) => fail(res, 404, "NOT_FOUND", "Route not found.");

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (err instanceof AppError) return fail(res, err.status, err.code, err.message, err.extra);
  if (err.type === "entity.parse.failed" || err.type === "entity.too.large") return fail(res, err.status || 400, "BAD_BODY", "Invalid request body.");
  console.error("[error]", req.method, req.originalUrl, err);
  return fail(res, 500, "INTERNAL_ERROR", config.isProd ? "Something went wrong." : err.message);
}

module.exports = { notFound, errorHandler };
