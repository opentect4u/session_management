const { tooMany } = require("../utils/errors");

/** Small in-memory per-IP limiter. For several server instances, move the counters to Redis/DB. */
function rateLimit({ windowMs, max }) {
  const hits = new Map();
  setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (v.resetAt <= now) hits.delete(k); }, windowMs).unref();
  return (req, res, next) => {
    const now = Date.now();
    const entry = hits.get(req.ip);
    if (!entry || entry.resetAt <= now) { hits.set(req.ip, { count: 1, resetAt: now + windowMs }); return next(); }
    if (++entry.count > max) {
      res.set("Retry-After", String(Math.ceil((entry.resetAt - now) / 1000)));
      throw tooMany("Too many requests. Please wait a few minutes and try again.");
    }
    next();
  };
}

module.exports = rateLimit;
