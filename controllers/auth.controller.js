const { randomUUID } = require("node:crypto");
const config = require("../config");
const UserModel = require("../models/user.model");
const CaptchaModel = require("../models/captcha.model");
const History = require("../models/loginHistory.model");
const Auth = require("../services/auth.service");
const Scope = require("../services/scope.service");
const { getPublicKey, decryptPayload, encryptionRequired } = require("../utils/passwordTransport");
const { createCaptchaImage } = require("../utils/captchaImage");
const { burnTime } = require("../utils/password");
const { badRequest, unauthorized, AppError } = require("../utils/errors");
const { ok } = require("../utils/response");
const { clientInfo, requiredString } = require("../utils/request");
const { setSessionCookie, clearSessionCookie } = require("../utils/sessionCookie");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const { events } = config;

/** The branch part of every session response: what is chosen now and what the user may choose from. */
const scopePayload = (scope, options) => ({ scope, scopeOptions: options });

const sessionPayload = (auth) => ({
  user: auth.user,
  csrfToken: auth.csrfToken,
  permissionVersion: auth.permissionVersion,
  permissionsRefreshed: auth.permissionsRefreshed,
  idleExpiresAt: auth.idleExpiresAt,
  absoluteExpiresAt: auth.absoluteExpiresAt,
});

/** GET /auth/public-key - the browser encrypts the password with this before sending it. */
const publicKey = (req, res) => ok(res, getPublicKey());

/** GET /auth/captcha - a fresh single-use challenge. */
async function captcha(req, res) {
  const id = randomUUID();
  const { text, image } = createCaptchaImage();
  await CaptchaModel.create(id, text, config.auth.captcha.ttlMs);
  ok(res, { captchaId: id, image, expiresInSeconds: config.auth.captcha.ttlMs / 1000 });
}

/** POST /auth/login  { username, captchaId, captchaAnswer, encryptedPassword } */
async function login(req, res) {
  const client = clientInfo(req);
  const username = requiredString(req.body, "username", { max: 50 });
  const captchaId = requiredString(req.body, "captchaId", { max: 40 });
  const captchaAnswer = requiredString(req.body, "captchaAnswer", { max: 10 });
  const encrypted = req.body.encryptedPassword;
  if (!UUID.test(captchaId)) throw badRequest("CAPTCHA_INVALID", "Captcha is invalid or expired. Please try a new one.");

  // 1) captcha first: no password is even looked at until a human-solvable challenge is answered (single use).
  if (!(await CaptchaModel.consume(captchaId, captchaAnswer))) {
    await History.record({ username, event: events.CAPTCHA_FAILED, ...client });
    throw badRequest("CAPTCHA_INVALID", "Captcha is incorrect or expired. Please try again.");
  }

  // 2) decrypt the password; the payload is bound to this captcha id, so a captured request cannot be replayed.
  let password;
  if (encryptionRequired || encrypted) {
    const payload = decryptPayload(encrypted);
    if (payload.c !== captchaId || typeof payload.p !== "string") throw badRequest("DECRYPTION_FAILED", "Invalid request. Reload the page and try again.");
    password = payload.p;
  } else {
    password = String(req.body.password ?? "");
  }
  if (!password || password.length > config.auth.password.maxLength) throw unauthorized("INVALID_CREDENTIALS", "Invalid username or password.");

  // 3) user checks (same generic error for unknown/inactive users, so usernames cannot be probed)
  const user = await UserModel.findForLogin(username);
  const ctx = { username, client };
  if (!user) {
    await burnTime(password);
    await History.record({ username, event: events.LOGIN_FAILED, reason: "UNKNOWN_USER", ...client });
    throw unauthorized("INVALID_CREDENTIALS", "Invalid username or password.");
  }
  if (user.locked_at) {
    await History.record({ userId: user.id, username, event: events.LOGIN_BLOCKED, reason: "ACCOUNT_LOCKED", ...client });
    throw Auth.lockedError();
  }
  if (!user.is_active || !user.login_allowed) {
    await burnTime(password);
    await History.record({ userId: user.id, username, event: events.LOGIN_BLOCKED, reason: "ACCOUNT_INACTIVE", ...client });
    throw unauthorized("INVALID_CREDENTIALS", "Invalid username or password.");
  }

  // 4) password (a wrong one counts toward the lock limit)
  if (!(await Auth.checkPassword(user, password))) await Auth.failWrongPassword(user, ctx);

  // 5) branch scope: users with exactly one branch go straight in, Superadmin / multi-branch users choose next
  const authUser = { id: user.id, role: user.role_code };
  const options = await Scope.optionsFor(authUser);
  const initial = Scope.initialScope(authUser, options);
  const initialBranch = initial && options.branches.find((b) => b.id === initial.branchId);

  // 6) session + audit, all in one transaction; the cookie is only set after it committed
  const s = await Auth.completeLogin(user, { username, client, scope: initial });
  setSessionCookie(res, s.raw, s.absoluteExpiresAt);
  ok(res, {
    user: { id: user.id, tenantId: user.tenant_id, name: user.name, roleId: user.role_id, role: user.role_code, roleName: user.role_name, roleLevel: user.hierarchy_level },
    csrfToken: s.csrfToken,
    permissionVersion: user.permission_version,
    idleExpiresAt: s.idleExpiresAt,
    absoluteExpiresAt: s.absoluteExpiresAt,
    ...scopePayload(initial && { ...initial, branchName: initialBranch?.name ?? null }, options),
  });
}

/** GET /auth/session - who am I (also returns the CSRF token after a page reload). */
async function session(req, res) {
  ok(res, { ...sessionPayload(req.auth), ...scopePayload(req.auth.scope, await Scope.optionsFor(req.auth.user)) });
}

/** PUT /auth/scope  { mode: "GLOBAL" } | { mode: "BRANCH", branchId }  - choose or switch the working scope. */
async function selectScope(req, res) {
  const scope = await Scope.select(req.auth, req.body, clientInfo(req));
  ok(res, { scope });
}

/** POST /auth/logout - signs the user out of EVERY device. */
async function logout(req, res) {
  await Auth.signOutEverywhere(req.auth.user.id, clientInfo(req));
  clearSessionCookie(res);
  ok(res, { message: "Signed out." });
}

/** POST /auth/change-password  { encryptedPayload }  payload = { cp: current, np: new, t } */
async function changePassword(req, res) {
  const client = clientInfo(req);
  const { id } = req.auth.user;
  const payload = decryptPayload(req.body?.encryptedPayload);
  const { cp: current, np: next } = payload;
  const { newPasswordMinLength, maxLength } = config.auth.password;
  if (typeof current !== "string" || typeof next !== "string") throw badRequest("VALIDATION_ERROR", "Both passwords are required.");
  if (next.length < newPasswordMinLength || next.length > maxLength) throw badRequest("WEAK_PASSWORD", `New password must be ${newPasswordMinLength}-${maxLength} characters.`);
  if (next === current) throw badRequest("WEAK_PASSWORD", "New password must be different from the current one.");

  const user = await UserModel.findForPasswordCheck(id);
  if (!(await Auth.checkPassword(user, current))) await Auth.failWrongPassword({ id }, { username: user.username, client });

  await Auth.applyNewPassword(id, user.username, next, client);
  clearSessionCookie(res);
  ok(res, { message: "Password changed. Please sign in again." });
}

/** POST /auth/users/:id/unlock - admin only. */
async function unlockUser(req, res) {
  const targetId = Number(req.params.id);
  if (!Number.isInteger(targetId) || targetId <= 0) throw badRequest("VALIDATION_ERROR", "Invalid user id.");
  const target = await UserModel.findBasic(targetId);
  if (!target) throw new AppError(404, "NOT_FOUND", "User not found.");
  await Auth.unlockAccount(target, req.auth.user.id, clientInfo(req));
  ok(res, { message: "Account unlocked." });
}

module.exports = { publicKey, captcha, login, session, selectScope, logout, changePassword, unlockUser };
