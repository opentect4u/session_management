/** An error that is safe to show to the client. Anything else becomes a generic 500. */
class AppError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

const badRequest = (code, message, extra) => new AppError(400, code, message, extra);
const unauthorized = (code, message, extra) => new AppError(401, code, message, extra);
const forbidden = (code, message, extra) => new AppError(403, code, message, extra);
const locked = (code, message, extra) => new AppError(423, code, message, extra);
const tooMany = (message, extra) => new AppError(429, "RATE_LIMITED", message, extra);

module.exports = { AppError, badRequest, unauthorized, forbidden, locked, tooMany };
