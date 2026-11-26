const config = require("../config");

const base = (({ httpOnly, secure, sameSite, path }) => ({ httpOnly, secure, sameSite, path }))(config.auth.cookie);

/** Browser-session cookie that also carries the hard (absolute) expiry. */
const setSessionCookie = (res, rawSessionId, absoluteExpiresAt) =>
  res.cookie(config.auth.cookie.name, rawSessionId, { ...base, expires: absoluteExpiresAt });

const clearSessionCookie = (res) => res.clearCookie(config.auth.cookie.name, base);

module.exports = { setSessionCookie, clearSessionCookie };
