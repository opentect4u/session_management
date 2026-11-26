const { f_select, f_insert, f_delete } = require("./MasterModule");

const create = (s, tx) =>
  f_insert(
    "auth.sessions",
    `(session_id_hash, tenant_id, user_id, permission_version, department_scope, csrf_token, ip, user_agent,
      created_at, last_seen_at, idle_expires_at, absolute_expires_at, scope_mode, scope_branch_id)`,
    "($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11,$12,$13)",
    "", 0,
    [s.hash, s.tenantId, s.userId, s.permissionVersion, s.departmentScope ?? null, s.csrfToken, s.ip, s.userAgent, s.now, s.idleExpiresAt, s.absoluteExpiresAt,
      s.scope?.mode ?? null, s.scope?.branchId ?? null],
    tx,
  );

/** The one lookup done on every request: session by primary key + the user's current state. */
const findByHash = async (hash) => {
  const r = await f_select(
    `s.*, u.name, u.is_active, u.login_allowed, r.role_id, r.role_code, r.role_name, r.hierarchy_level, us.locked_at, COALESCE(us.permission_version, 1) AS current_permission_version, cb.branch_name AS scope_branch_name`,
    `auth.sessions s
       JOIN auth.users u ON u.user_id = s.user_id
       JOIN auth.roles r ON r.role_id = u.role_id
       LEFT JOIN auth.user_security us ON us.user_id = s.user_id
       LEFT JOIN auth.branches cb ON cb.branch_id = s.scope_branch_id`,
    "s.session_id_hash = $1", "", [hash],
  );
  return r.rows[0] || null;
};

const touch = (hash, now, idleExpiresAt, tx) =>
  f_insert("auth.sessions", "last_seen_at = $2, idle_expires_at = LEAST($3, absolute_expires_at)", "",
    "session_id_hash = $1 AND revoked_at IS NULL", 1, [hash, now, idleExpiresAt], tx);

const syncPermissionVersion = (hash, version, tx) =>
  f_insert("auth.sessions", "permission_version = $2", "", "session_id_hash = $1", 1, [hash, version], tx);

/** Store the branch scope of a live session. scope = { mode, branchId } or null to send the user back to the chooser. */
const setScope = async (hash, scope, tx) => {
  const r = await f_insert("auth.sessions", "scope_mode = $2, scope_branch_id = $3", "", "session_id_hash = $1 AND revoked_at IS NULL", 1,
    [hash, scope?.mode ?? null, scope?.branchId ?? null], tx);
  return r.rowCount > 0;
};

/** Revoke every live session of a user (logout, password change, deactivation, lock, new login). Returns how many. */
const revokeAllForUser = async (userId, reason, tx) => {
  const r = await f_insert("auth.sessions", "revoked_at = now(), revoke_reason = $2", "", "user_id = $1 AND revoked_at IS NULL", 1, [userId, reason], tx);
  return r.rowCount;
};

const countActiveForUser = async (userId, tx) => {
  const r = await f_select("count(*)::int AS n", "auth.sessions",
    "user_id = $1 AND revoked_at IS NULL AND idle_expires_at > now() AND absolute_expires_at > now()", "", [userId], tx);
  return r.rows[0].n;
};

/** Serialise concurrent logins of one user for the length of the transaction. */
const lockUserLogin = (userId, tx) => f_select("pg_advisory_xact_lock(hashtext('auth.login'), $1)", "", "", "", [userId], tx);

/** Housekeeping: drop expired rows and revoked rows older than the retention window. Audit lives in auth.login_history. */
const deleteExpired = async (revokedRetentionMs) => {
  const r = await f_delete("auth.sessions",
    `absolute_expires_at < now() OR idle_expires_at < now()
     OR (revoked_at IS NOT NULL AND revoked_at < now() - ($1 * interval '1 millisecond'))`, [revokedRetentionMs]);
  return r.rowCount;
};

module.exports = { create, findByHash, touch, syncPermissionVersion, setScope, revokeAllForUser, countActiveForUser, lockUserLogin, deleteExpired };
