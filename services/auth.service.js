/**
 * Reusable auth rules. Each function that changes data runs as ONE transaction (withTransaction):
 * it commits only after every step succeeded and rolls everything back on any error.
 * Errors meant for the client are thrown AFTER the commit, so the data they describe (e.g. the failed-attempt count) is kept.
 */
const config = require("../config");
const { withTransaction } = require("../models/MasterModule");
const UserModel = require("../models/user.model");
const SessionModel = require("../models/session.model");
const History = require("../models/loginHistory.model");
const { AppError, unauthorized, locked } = require("../utils/errors");
const { randomToken, sha256Hex } = require("../utils/crypto");
const { hashPassword, verifyScrypt } = require("../utils/password");

const { session: S, maxFailedAttempts, singleSessionPolicy } = config.auth;
const { events, revokeReasons } = config;

/** True if `plain` matches the stored scrypt hash. No side effects. */
const checkPassword = (user, plain) => verifyScrypt(plain, user.password_hash);

const lockedError = () => locked("ACCOUNT_LOCKED", "Your account is locked after too many failed attempts. Please contact the administrator.");

/** Count a wrong password; at the limit lock the account and kill its sessions. Always throws (after committing). */
async function failWrongPassword(user, { username, client }) {
  const { failedAttempts, locked: nowLocked } = await withTransaction(async (tx) => {
    const result = await UserModel.registerFailedAttempt(user.id, maxFailedAttempts, tx);
    if (result.locked) {
      await SessionModel.revokeAllForUser(user.id, revokeReasons.ACCOUNT_LOCKED, tx);
      await History.record({ userId: user.id, username, event: events.ACCOUNT_LOCKED, reason: `${result.failedAttempts} failed attempts`, ...client }, tx);
    } else {
      await History.record({ userId: user.id, username, event: events.LOGIN_FAILED, reason: "WRONG_PASSWORD", ...client }, tx);
    }
    return result;
  });
  if (nowLocked) throw lockedError();
  throw unauthorized("INVALID_CREDENTIALS", "Invalid username or password.", { attemptsRemaining: Math.max(maxFailedAttempts - failedAttempts, 0) });
}

/**
 * Verified user -> new session. One transaction: apply the one-device policy, create the session, reset the failed
 * counter and write the audit rows. Nothing is kept unless all of it succeeds.
 */
async function completeLogin(user, { username, client, scope = null }) {
  const raw = randomToken(S.idBytes);
  const csrfToken = randomToken(S.csrfBytes);
  const now = new Date();
  const absoluteExpiresAt = new Date(now.getTime() + S.absoluteTimeoutMs);
  const idleExpiresAt = new Date(Math.min(now.getTime() + S.idleTimeoutMs, absoluteExpiresAt.getTime()));

  await withTransaction(async (tx) => {
    await SessionModel.lockUserLogin(user.id, tx);
    let replaced = 0;
    if (singleSessionPolicy === "deny") {
      if (await SessionModel.countActiveForUser(user.id, tx)) throw new AppError(409, "ALREADY_LOGGED_IN", "This account is already signed in on another device.");
    } else {
      replaced = await SessionModel.revokeAllForUser(user.id, revokeReasons.NEW_LOGIN, tx);
    }
    await SessionModel.create({
      hash: sha256Hex(raw), tenantId: user.tenant_id, userId: user.id, permissionVersion: user.permission_version,
      csrfToken, ip: client.ip, userAgent: client.userAgent, now, idleExpiresAt, absoluteExpiresAt, scope,
    }, tx);
    await UserModel.markLoginSuccess(user.id, tx);
    if (replaced) await History.record({ userId: user.id, username, event: events.SESSION_REPLACED, reason: `${replaced} older session(s) signed out`, ...client }, tx);
    await History.record({ userId: user.id, username, event: events.LOGIN_SUCCESS, ...client }, tx);
  });

  return { raw, csrfToken, idleExpiresAt, absoluteExpiresAt };
}

/** Logout = every session of the user is revoked. */
const signOutEverywhere = (userId, client) =>
  withTransaction(async (tx) => {
    await SessionModel.revokeAllForUser(userId, revokeReasons.LOGOUT, tx);
    await History.record({ userId, event: events.LOGOUT, ...client }, tx);
  });

/** Store the new password and sign the user out everywhere, atomically. */
async function applyNewPassword(userId, username, newPlain, client) {
  const hash = await hashPassword(newPlain);
  await withTransaction(async (tx) => {
    await UserModel.setPasswordHash(userId, hash, tx);
    await SessionModel.revokeAllForUser(userId, revokeReasons.PASSWORD_CHANGED, tx);
    await History.record({ userId, username, event: events.PASSWORD_CHANGED, ...client }, tx);
  });
}

const unlockAccount = (target, actorId, client) =>
  withTransaction(async (tx) => {
    await UserModel.unlock(target.id, tx);
    await History.record({ userId: target.id, username: target.username, event: events.ACCOUNT_UNLOCKED, reason: `by user ${actorId}`, ...client }, tx);
  });

/** Use after deactivating a user in the user-management module (pass that module's `tx` to commit together). */
const onUserDeactivated = (userId, tx) => SessionModel.revokeAllForUser(userId, revokeReasons.USER_DEACTIVATED, tx);

/** Use after changing a user's role/permissions: their next request refreshes their rights. */
const onPermissionsChanged = (userId, tx) => UserModel.bumpPermissionVersion(userId, tx);

module.exports = { checkPassword, failWrongPassword, lockedError, completeLogin, signOutEverywhere, applyNewPassword, unlockAccount, onUserDeactivated, onPermissionsChanged };
