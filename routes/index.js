const router = require("express").Router();

router.get("/health", (req, res) => res.json({ success: true, data: { status: "ok" } }));
router.use("/auth", require("./auth.routes"));
// router.use("/your-module", require("./your-module.routes"));   // other modules plug in here: authenticate, requireScope, csrfProtection

module.exports = router;
