const { f_select, f_insert } = require("./MasterModule");

const LOGIN_TABLES = `auth.users u
  JOIN auth.roles r ON r.role_id = u.role_id
  LEFT JOIN auth.user_security us ON us.user_id = u.user_id`;

/** User + security state, looked up by login name. */
const findForLogin = async (username) => {
  const r = await f_select(
    `u.user_id AS id, u.branch_id AS tenant_id, u.name, u.is_active, u.login_allowed,
     r.role_id, r.role_code, r.role_name, r.hierarchy_level,
     u.password_hash, us.failed_attempts, us.locked_at,
     COALESCE(us.permission_version, 1) AS permission_version`,
    LOGIN_TABLES, "u.username = $1", "", [username],
  );
  return r.rows[0] || null;
};

const findForPasswordCheck = async (id) => {
  const r = await f_select("u.user_id AS id, u.username, u.password_hash", LOGIN_TABLES, "u.user_id = $1", "", [id]);
  return r.rows[0] || null;
};

const findBasic = async (id) => {
  const r = await f_select("user_id AS id, username", "auth.users", "user_id = $1", "", [id]);
  return r.rows[0] || null;
};

/** Create a user (used by scripts/create_user.js; `passwordHash` comes from utils/password.hashPassword). */
const create = async ({ username, name, passwordHash, roleId, branchId }, tx) => {
  const r = await f_insert("auth.users", "(username, name, password_hash, role_id, branch_id)", "($1,$2,$3,$4,$5)", "", 0,
    [username, name, passwordHash, roleId, branchId], tx, 
    `INSERT INTO auth.users (username, name, password_hash, role_id, branch_id) VALUES ($1,$2,$3,$4,$5) RETURNING user_id AS id`);
  return r.rows[0].id;
};

/** Atomically count one more wrong password; locks the account at the limit. Returns { failedAttempts, locked }. */
const registerFailedAttempt = async (id, maxAttempts, tx) => {
  const r = await f_insert(null, null, null, "", 0, [id, maxAttempts], tx,
    `INSERT INTO auth.user_security AS us (user_id, failed_attempts, locked_at)
          VALUES ($1, 1, CASE WHEN 1 >= $2 THEN now() END)
     ON CONFLICT (user_id) DO UPDATE
             SET failed_attempts = us.failed_attempts + 1,
                 locked_at = CASE WHEN us.locked_at IS NULL AND us.failed_attempts + 1 >= $2 THEN now() ELSE us.locked_at END
       RETURNING failed_attempts, locked_at`);
  return { failedAttempts: r.rows[0].failed_attempts, locked: r.rows[0].locked_at !== null };
};

const markLoginSuccess = (id, tx) =>
  f_insert(null, null, null, "", 0, [id], tx,
    `INSERT INTO auth.user_security AS us (user_id, last_login_at) VALUES ($1, now())
     ON CONFLICT (user_id) DO UPDATE SET failed_attempts = 0, last_login_at = now()`);

/** Store a new password hash and stamp the change time. */
const setPasswordHash = async (id, hash, tx) => {
  await f_insert("auth.users", "password_hash = $2", "", "user_id = $1", 1, [id, hash], tx);
  return f_insert(null, null, null, "", 0, [id], tx,
    `INSERT INTO auth.user_security (user_id, password_changed_at) VALUES ($1, now())
     ON CONFLICT (user_id) DO UPDATE SET password_changed_at = now()`);
};

const unlock = (id, tx) =>
  f_insert(null, null, null, "", 0, [id], tx,
    `INSERT INTO auth.user_security (user_id) VALUES ($1)
     ON CONFLICT (user_id) DO UPDATE SET failed_attempts = 0, locked_at = NULL`);

/** Call after an admin edits a user's role/permissions: live sessions pick it up on their next request. */
const bumpPermissionVersion = (id, tx) =>
  f_insert(null, null, null, "", 0, [id], tx,
    `INSERT INTO auth.user_security AS us (user_id, permission_version) VALUES ($1, 2)
     ON CONFLICT (user_id) DO UPDATE SET permission_version = us.permission_version + 1
       RETURNING permission_version`);

/** Change a user's role and bump permission_version so their live session adopts it on the very next request. */
const setRole = async (id, roleId, tx) => {
  const r = await f_insert("auth.users", "role_id = $2", "", "user_id = $1", 1, [id, roleId], tx);
  if (r.rowCount) await bumpPermissionVersion(id, tx);
  return r.rowCount > 0;
};

module.exports = { findForLogin, findForPasswordCheck, findBasic, create, registerFailedAttempt, markLoginSuccess, setPasswordHash, unlock, bumpPermissionVersion, setRole };
