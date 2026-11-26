const router = require("express").Router();
const config = require("../config");
const ctrl = require("../controllers/auth.controller");
const authenticate = require("../middleware/authenticate");
const csrfProtection = require("../middleware/csrf");
const requireRole = require("../middleware/requireRole");
const rateLimit = require("../middleware/rateLimit");

const { windowMs, loginMax, captchaMax } = config.auth.rateLimit;

// public
router.get("/public-key", ctrl.publicKey);
router.get("/captcha", rateLimit({ windowMs, max: captchaMax }), ctrl.captcha);
router.post("/login", rateLimit({ windowMs, max: loginMax }), ctrl.login);

// signed-in (state-changing routes also need the CSRF header)
router.get("/session", authenticate, ctrl.session);
router.put("/scope", authenticate, csrfProtection, ctrl.selectScope);
router.post("/logout", authenticate, csrfProtection, ctrl.logout);
router.post("/change-password", authenticate, csrfProtection, ctrl.changePassword);
router.post("/users/:id/unlock", authenticate, csrfProtection, requireRole(...config.auth.unlockRoles), ctrl.unlockUser);

module.exports = router;
