const config = require("../config");
const SessionModel = require("../models/session.model");
const CaptchaModel = require("../models/captcha.model");

/** Every cleanupIntervalMs: remove expired/revoked sessions and stale captchas. auth.login_history is never touched. */
function startSessionCleanup() {
  const run = async () => {
    try {
      const sessions = await SessionModel.deleteExpired(config.auth.session.revokedRetentionMs);
      const captchas = await CaptchaModel.deleteExpired();
      if (sessions || captchas) console.log(`[cleanup] removed ${sessions} session(s), ${captchas} captcha(s)`);
    } catch (err) {
      console.error("[cleanup] failed:", err.message);
    }
  };
  run();
  return setInterval(run, config.auth.session.cleanupIntervalMs).unref();
}

module.exports = { startSessionCleanup };
