const { forbidden } = require("../utils/errors");

/** Use AFTER authenticate on every data route (lists, reports, masters, bookings): refuses until the user chose Global / a branch. */
module.exports = (req, res, next) => {
  if (!req.auth.scope) throw forbidden("SCOPE_REQUIRED", "Choose a branch (or global view) before continuing.");
  next();
};
