const config = require("../config");
const { forbidden } = require("../utils/errors");
const { safeEqual } = require("../utils/crypto");

/** Use AFTER authenticate. Every request that can change data must carry the session's X-CSRF-Token header. */
function csrfProtection(req, res, next) {
  if (config.auth.csrf.safeMethods.includes(req.method)) return next();
  const sent = req.get(config.auth.csrf.headerName);
  if (!sent || !safeEqual(sent, req.auth.csrfToken)) throw forbidden("CSRF_INVALID", "Security token missing or invalid. Reload the page and try again.");
  next();
}

module.exports = csrfProtection;
