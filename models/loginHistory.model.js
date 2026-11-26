const { f_insert } = require("./MasterModule");

/** Append-only audit record. Pass `tx` to make it part of the surrounding transaction (it commits or rolls back with it). */
const record = ({ userId = null, username = null, event, reason = null, ip = null, userAgent = null }, tx) =>
  f_insert("auth.login_history", "(user_id, username, event, reason, ip, user_agent)", "($1,$2,$3,$4,$5,$6)", "", 0,
    [userId, username ? String(username).slice(0, 100) : null, event, reason, ip, userAgent], tx);

module.exports = { record };
