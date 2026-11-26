const { forbidden } = require("../utils/errors");

/** requireRole("ADMIN") - use AFTER authenticate. */
const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.auth.user.role)) throw forbidden("FORBIDDEN", "You do not have permission to do this.");
  next();
};

module.exports = requireRole;
