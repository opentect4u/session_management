const config = require("../config");
const { badRequest } = require("./errors");

const clientInfo = (req) => ({ ip: req.ip || null, userAgent: (req.get("user-agent") || "").slice(0, 400) || null });

/** Read a required string field from the body. Throws a 400 with a clear message if missing or too long. */
function requiredString(body, field, { max = 200 } = {}) {
  const value = body?.[field];
  if (typeof value !== "string" || !value.trim()) throw badRequest("VALIDATION_ERROR", `${field} is required.`);
  if (value.length > max) throw badRequest("VALIDATION_ERROR", `${field} is too long.`);
  return value.trim();
}

const getCookie = (req) => req.cookies?.[config.auth.cookie.name];

module.exports = { clientInfo, requiredString, getCookie };
