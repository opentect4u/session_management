const config = require("../config");
const SessionModel = require("../models/session.model");
const { unauthorized, locked } = require("../utils/errors");
const { sha256Hex } = require("../utils/crypto");
const { getCookie } = require("../utils/request");
const { clearSessionCookie } = require("../utils/sessionCookie");
const Scope = require("../services/scope.service");

const { idleTimeoutMs, touchIntervalMs } = config.auth.session;

const REVOKED_MESSAGES = {
  NEW_LOGIN: "You were signed out because your account was used to sign in on another device.",
  PASSWORD_CHANGED: "Your password was changed. Please sign in again.",
  USER_DEACTIVATED: "Your account has been deactivated.",
  ACCOUNT_LOCKED: "Your account is locked. Please contact the administrator.",
};

/**
 * Validates the session cookie (one primary-key lookup) and sets req.auth.
 * Rejects revoked / idle-expired / absolute-expired sessions and deactivated or locked users.
 */
async function authenticate(req, res, next) {
  const raw = getCookie(req);
  if (!raw) throw unauthorized("UNAUTHENTICATED", "Please sign in.");

  const hash = sha256Hex(raw);
  const s = await SessionModel.findByHash(hash);
  const reject = (code, message, extra) => { clearSessionCookie(res); return unauthorized(code, message, extra); };

  if (!s) throw reject("UNAUTHENTICATED", "Please sign in.");
  if (s.revoked_at) throw reject("SESSION_REVOKED", REVOKED_MESSAGES[s.revoke_reason] || "You have been signed out.", { reason: s.revoke_reason });

  const now = new Date();
  if (now > s.absolute_expires_at) throw reject("SESSION_EXPIRED", "Your session has ended. Please sign in again.", { reason: "ABSOLUTE" });
  if (now > s.idle_expires_at) throw reject("SESSION_EXPIRED", "You were signed out due to inactivity.", { reason: "IDLE" });

  if (!s.is_active || !s.login_allowed) {
    await SessionModel.revokeAllForUser(s.user_id, config.revokeReasons.USER_DEACTIVATED);
    throw reject("ACCOUNT_DISABLED", "Your account has been deactivated.");
  }
  if (s.locked_at) {
    await SessionModel.revokeAllForUser(s.user_id, config.revokeReasons.ACCOUNT_LOCKED);
    clearSessionCookie(res);
    throw locked("ACCOUNT_LOCKED", REVOKED_MESSAGES.ACCOUNT_LOCKED);
  }

  // Live permission sync: an admin changed this user's rights -> adopt the new version on this very request.
  let permissionsRefreshed = false;
  if (s.permission_version !== s.current_permission_version) {
    await SessionModel.syncPermissionVersion(hash, s.current_permission_version);
    permissionsRefreshed = true;
  }

  // Branch scope of this session. If the user's rights just changed, make sure the stored choice is still allowed
  // (e.g. they were removed from that branch); otherwise send them back to the chooser.
  const user = { id: s.user_id, role: s.role_code };
  let scope = s.scope_mode ? { mode: s.scope_mode, branchId: s.scope_branch_id, branchName: s.scope_branch_name } : null;
  if (scope && permissionsRefreshed && !(await Scope.stillAllowed(user, scope))) {
    await SessionModel.setScope(hash, null);
    scope = null;
  }

  // Write last_seen_at at most once per touch interval, not on every click.
  if (now - s.last_seen_at >= touchIntervalMs) {
    await SessionModel.touch(hash, now, new Date(now.getTime() + idleTimeoutMs));
    s.last_seen_at = now;
    s.idle_expires_at = new Date(Math.min(now.getTime() + idleTimeoutMs, s.absolute_expires_at.getTime()));
    
  }
  req.auth = {
    sessionHash: hash,
    csrfToken: s.csrf_token,
    permissionVersion: s.current_permission_version,
    permissionsRefreshed,
    idleExpiresAt: s.idle_expires_at,
    absoluteExpiresAt: s.absolute_expires_at,
    departmentScope: s.department_scope,
    scope, // { mode: "GLOBAL"|"BRANCH", branchId, branchName } or null until chosen
    user: { id: s.user_id, tenantId: s.tenant_id, name: s.name, roleId: s.role_id, role: s.role_code, roleName: s.role_name, roleLevel: s.hierarchy_level },
  };
  next();
}

module.exports = authenticate;
