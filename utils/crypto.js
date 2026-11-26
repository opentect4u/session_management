const { createHash, randomBytes, timingSafeEqual } = require("node:crypto");

/** URL-safe random token with `bytes` bytes of entropy (32 bytes = 256 bits). */
const randomToken = (bytes) => randomBytes(bytes).toString("base64url");

const sha256Hex = (value) => createHash("sha256").update(value).digest("hex");

/** Constant-time string comparison (safe for tokens and hashes). */
function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}

module.exports = { randomToken, sha256Hex, safeEqual };
