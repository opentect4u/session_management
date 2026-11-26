/**
 * End-to-end auth tests against a real Postgres (needs PG_* env vars and `npm run db:migrate` applied first).
 * Creates four throw-away users and deletes them afterwards. Run: AUTH_RATE_LOGIN_MAX=1000 npm test
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const { createHash, publicEncrypt, constants, randomUUID } = require("node:crypto");
const app = require("../app");
const config = require("../config");
const { pool } = require("../config/db");
// tests may use the pool directly for set-up and for inspecting the DB from the outside
const query = (text, params) => pool.query(text, params);
const CaptchaModel = require("../models/captcha.model");
const { hashPassword } = require("../utils/password");

const USER = { username: "__t_user__", password: "Test@12345" };
const ADMIN = { username: "__t_admin__", password: "Admin@12345" };
const SUPER = { username: "__t_super__", password: "Super@12345" };
const OTHER = { username: "__t_other__", password: "Other@12345" };
const ROLE = { SUPERADMIN: 1, ADMIN: 2, EMPLOYEE: 3, OTHER: 4 };
let base, server, publicKey, ids = {};

const sha256 = (s) => createHash("sha256").update(s).digest("hex");

async function createEmployee({ username, password }, roleId) {
  const { rows } = await query(
    `INSERT INTO auth.users (branch_id, name, username, password_hash, role_id) VALUES ((SELECT min(branch_id) FROM auth.branches), $1, $1, $2, $3) RETURNING user_id`,
    [username, await hashPassword(password), roleId],
  );
  return rows[0].user_id;
}

async function api(method, path, { body, cookie, csrf } = {}) {
  const res = await fetch(base + path, {
    method,
    headers: { "content-type": "application/json", ...(cookie && { cookie }), ...(csrf && { "x-csrf-token": csrf }) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json();
  return { status: res.status, json, setCookie: res.headers.get("set-cookie") };
}

const encrypt = (obj) => publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.from(JSON.stringify({ ...obj, t: Date.now() }))).toString("base64");

/** Log in using a captcha whose answer we know (we create the challenge directly, as a browser would fetch one). */
async function login({ username, password }, overrides = {}) {
  const captchaId = randomUUID();
  await CaptchaModel.create(captchaId, "ABCDE", 60000);
  return api("POST", "/api/auth/login", {
    body: { username, captchaId, captchaAnswer: "abcde", encryptedPassword: encrypt({ p: password, c: captchaId }), ...overrides },
  });
}
const cookieOf = (r) => r.setCookie.split(";")[0];

test.before(async () => {
  await new Promise((resolve) => { server = app.listen(0, () => { base = `http://127.0.0.1:${server.address().port}`; resolve(); }); });
  publicKey = (await api("GET", "/api/auth/public-key")).json.data.publicKey;
  ids.user = await createEmployee(USER, ROLE.EMPLOYEE);
  ids.admin = await createEmployee(ADMIN, ROLE.ADMIN);
  ids.super = await createEmployee(SUPER, ROLE.SUPERADMIN);
  ids.other = await createEmployee(OTHER, ROLE.OTHER);
});

test.after(async () => {
  const list = Object.values(ids);
  await query("DELETE FROM auth.users WHERE user_id = ANY($1)", [list]); // cascades to auth.user_security/sessions
  await query("DELETE FROM auth.login_history WHERE user_id = ANY($1) OR username IN ($2,$3,$4,$5,'__t_nobody__')", [list, USER.username, ADMIN.username, SUPER.username, OTHER.username]);
  server.close();
  await pool.end();
});

test("captcha endpoint returns an image and a single-use id", async () => {
  const r = await api("GET", "/api/auth/captcha");
  assert.equal(r.status, 200);
  assert.match(r.json.data.image, /^data:image\/svg\+xml;base64,/);
  assert.match(r.json.data.captchaId, /^[0-9a-f-]{36}$/);
});

test("login refuses missing/wrong captcha, plain-text passwords and unknown users", async () => {
  assert.equal((await api("POST", "/api/auth/login", { body: { username: USER.username } })).status, 400);
  const wrong = await login(USER, { captchaAnswer: "ZZZZZ" });
  assert.equal(wrong.json.error.code, "CAPTCHA_INVALID");
  const captchaId = randomUUID(); await CaptchaModel.create(captchaId, "ABCDE", 60000);
  const plain = await api("POST", "/api/auth/login", { body: { username: USER.username, captchaId, captchaAnswer: "ABCDE", password: USER.password } });
  assert.equal(plain.json.error.code, "ENCRYPTION_REQUIRED");
  const ghost = await login({ username: "__t_nobody__", password: "x" });
  assert.equal(ghost.status, 401);
  assert.equal(ghost.json.error.message, "Invalid username or password.");
});

test("captcha is single use (replaying the same challenge fails)", async () => {
  const captchaId = randomUUID(); await CaptchaModel.create(captchaId, "ABCDE", 60000);
  const body = { username: USER.username, captchaId, captchaAnswer: "ABCDE", encryptedPassword: encrypt({ p: "wrong", c: captchaId }) };
  assert.equal((await api("POST", "/api/auth/login", { body })).status, 401);
  assert.equal((await api("POST", "/api/auth/login", { body })).json.error.code, "CAPTCHA_INVALID");
});

test("successful login: hashed session id, secure cookie, CSRF token, password stored as scrypt", async () => {
  const r = await login(USER);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const raw = cookieOf(r).split("=")[1];
  assert.match(r.setCookie, /HttpOnly/i);
  assert.match(r.setCookie, /SameSite=Lax/i);
  assert.ok(Buffer.from(raw, "base64url").length === 32, "256-bit session id");
  const { rows } = await query("SELECT session_id_hash, csrf_token FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL", [ids.user]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].session_id_hash, sha256(raw), "DB stores SHA-256 of the id");
  assert.notEqual(rows[0].session_id_hash, raw);
  assert.equal(rows[0].csrf_token, r.json.data.csrfToken);
  const sec = await query("SELECT password_hash FROM auth.users WHERE user_id=$1", [ids.user]);
  assert.match(sec.rows[0].password_hash, /^scrypt\$/);
});

test("session endpoint works with cookie, 401 without; last_seen_at is throttled", async () => {
  assert.equal((await api("GET", "/api/auth/session")).status, 401);
  const r = await login(USER); const cookie = cookieOf(r);
  const a = await api("GET", "/api/auth/session", { cookie });
  assert.equal(a.status, 200);
  assert.equal(a.json.data.user.name, USER.username);
  const before = (await query("SELECT last_seen_at FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL", [ids.user])).rows[0].last_seen_at.getTime();
  await api("GET", "/api/auth/session", { cookie });
  await api("GET", "/api/auth/session", { cookie });
  const after = (await query("SELECT last_seen_at FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL", [ids.user])).rows[0].last_seen_at.getTime();
  assert.equal(after, before, "no write within the touch interval");
  // pretend the last write was 2 minutes ago -> next request writes again
  await query("UPDATE auth.sessions SET last_seen_at = last_seen_at - interval '2 minutes' WHERE user_id=$1 AND revoked_at IS NULL", [ids.user]);
  await api("GET", "/api/auth/session", { cookie });
  const later = (await query("SELECT last_seen_at FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL", [ids.user])).rows[0].last_seen_at.getTime();
  assert.ok(later > before - 60000);
});

test("only one device: a new login signs the old one out", async () => {
  const first = await login(USER); const c1 = cookieOf(first);
  const second = await login(USER); const c2 = cookieOf(second);
  const old = await api("GET", "/api/auth/session", { cookie: c1 });
  assert.equal(old.status, 401);
  assert.equal(old.json.error.code, "SESSION_REVOKED");
  assert.equal(old.json.error.reason, "NEW_LOGIN");
  assert.equal((await api("GET", "/api/auth/session", { cookie: c2 })).status, 200);
  const n = await query("SELECT count(*)::int n FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL", [ids.user]);
  assert.equal(n.rows[0].n, 1);
});

test("idle and absolute timeouts end the session", async () => {
  const r = await login(USER); const cookie = cookieOf(r);
  await query("UPDATE auth.sessions SET idle_expires_at = now() - interval '1 second' WHERE user_id=$1 AND revoked_at IS NULL", [ids.user]);
  const idle = await api("GET", "/api/auth/session", { cookie });
  assert.deepEqual([idle.status, idle.json.error.code, idle.json.error.reason], [401, "SESSION_EXPIRED", "IDLE"]);
  const r2 = await login(USER);
  await query("UPDATE auth.sessions SET absolute_expires_at = now() - interval '1 second' WHERE user_id=$1 AND revoked_at IS NULL", [ids.user]);
  const abs = await api("GET", "/api/auth/session", { cookie: cookieOf(r2) });
  assert.equal(abs.json.error.reason, "ABSOLUTE");
});

test("CSRF: state-changing request needs the matching X-CSRF-Token", async () => {
  const r = await login(USER); const cookie = cookieOf(r);
  assert.equal((await api("POST", "/api/auth/logout", { cookie })).json.error.code, "CSRF_INVALID");
  assert.equal((await api("POST", "/api/auth/logout", { cookie, csrf: "nope" })).status, 403);
  assert.equal((await api("GET", "/api/auth/session", { cookie })).status, 200, "still signed in after rejected attempts");
});

test("permission_version bump is picked up on the very next request", async () => {
  const r = await login(USER); const cookie = cookieOf(r);
  assert.equal((await api("GET", "/api/auth/session", { cookie })).json.data.permissionsRefreshed, false);
  await require("../services/auth.service").onPermissionsChanged(ids.user);
  const a = await api("GET", "/api/auth/session", { cookie });
  assert.equal(a.json.data.permissionsRefreshed, true);
  assert.equal(a.json.data.permissionVersion, 2);
  assert.equal((await api("GET", "/api/auth/session", { cookie })).json.data.permissionsRefreshed, false);
});

test("deactivating a user kills the session on the next request", async () => {
  const r = await login(USER); const cookie = cookieOf(r);
  await query("UPDATE auth.users SET is_active=false WHERE user_id=$1", [ids.user]);
  assert.equal((await api("GET", "/api/auth/session", { cookie })).json.error.code, "ACCOUNT_DISABLED");
  assert.equal((await login(USER)).status, 401, "cannot log in while deactivated");
  await query("UPDATE auth.users SET is_active=true WHERE user_id=$1", [ids.user]);
});

test("change password revokes sessions; old password stops working", async () => {
  const r = await login(USER); const cookie = cookieOf(r); const csrf = r.json.data.csrfToken;
  const bad = await api("POST", "/api/auth/change-password", { cookie, csrf, body: { encryptedPayload: encrypt({ cp: USER.password, np: "short" }) } });
  assert.equal(bad.json.error.code, "WEAK_PASSWORD");
  const ok = await api("POST", "/api/auth/change-password", { cookie, csrf, body: { encryptedPayload: encrypt({ cp: USER.password, np: "NewPass@9999" }) } });
  assert.equal(ok.status, 200);
  assert.equal((await api("GET", "/api/auth/session", { cookie })).status, 401);
  assert.equal((await login(USER)).status, 401);
  assert.equal((await login({ username: USER.username, password: "NewPass@9999" })).status, 200);
  USER.password = "NewPass@9999";
});

test("5 wrong passwords lock the account; only an admin can unlock it", async () => {
  const max = config.auth.maxFailedAttempts;
  let last;
  for (let i = 1; i <= max; i++) {
    last = await login({ username: USER.username, password: "wrong" + i });
    if (i < max) { assert.equal(last.status, 401); assert.equal(last.json.error.attemptsRemaining, max - i); }
  }
  assert.equal(last.status, 423);
  assert.equal(last.json.error.code, "ACCOUNT_LOCKED");
  assert.equal((await login(USER)).status, 423, "correct password is refused while locked");

  const admin = await login(ADMIN); const aCookie = cookieOf(admin);
  const u = await login(ADMIN); // (re-login keeps single session)
  const aC = cookieOf(u), aCsrf = u.json.data.csrfToken;
  assert.equal((await api("POST", `/api/auth/users/${ids.user}/unlock`, { cookie: aC })).status, 403, "needs CSRF");
  assert.equal((await api("POST", `/api/auth/users/${ids.user}/unlock`, { cookie: aC, csrf: aCsrf })).status, 200);
  assert.equal((await login(USER)).status, 200);
  void aCookie;
});

test("non-admin cannot unlock; logout kills every session; audit trail is kept", async () => {
  const r = await login(USER); const cookie = cookieOf(r); const csrf = r.json.data.csrfToken;
  assert.equal((await api("POST", `/api/auth/users/${ids.admin}/unlock`, { cookie, csrf })).status, 403);
  assert.equal((await api("POST", "/api/auth/logout", { cookie, csrf })).status, 200);
  assert.equal((await api("GET", "/api/auth/session", { cookie })).status, 401);
  const n = await query("SELECT count(*)::int n FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL", [ids.user]);
  assert.equal(n.rows[0].n, 0);
  const ev = await query("SELECT DISTINCT event FROM auth.login_history WHERE user_id=$1", [ids.user]);
  const events = ev.rows.map((e) => e.event);
  for (const e of ["LOGIN_SUCCESS", "LOGIN_FAILED", "ACCOUNT_LOCKED", "ACCOUNT_UNLOCKED", "LOGOUT", "PASSWORD_CHANGED", "SESSION_REPLACED"]) assert.ok(events.includes(e), `history has ${e}`);
});

test("every role is stored in auth.roles and returned by login and session", async () => {
  const expected = [[SUPER, "SUPERADMIN", "Superadmin", 1], [ADMIN, "ADMIN", "Admin", 2], [USER, "EMPLOYEE", "Employee", 3], [OTHER, "OTHER", "Other", 4]];
  for (const [who, code, name, level] of expected) {
    const r = await login(who);
    assert.equal(r.status, 200, JSON.stringify(r.json));
    const u = r.json.data.user;
    assert.deepEqual([u.role, u.roleName, u.roleLevel, u.roleId], [code, name, level, level], `login returns ${code}`);
    const s = await api("GET", "/api/auth/session", { cookie: cookieOf(r) });
    assert.equal(s.json.data.user.role, code, `session returns ${code}`);
  }
});

test("unlock is allowed for Superadmin and Admin only (Employee and Other get 403)", async () => {
  const attempt = async (who) => { const r = await login(who); return api("POST", `/api/auth/users/${ids.user}/unlock`, { cookie: cookieOf(r), csrf: r.json.data.csrfToken }); };
  assert.equal((await attempt(SUPER)).status, 200);
  assert.equal((await attempt(ADMIN)).status, 200);
  assert.equal((await attempt(OTHER)).status, 403);
  assert.equal((await attempt(USER)).status, 403);
});

test("changing a role takes effect on the user's next request (permission_version bump)", async () => {
  const UserModel = require("../models/user.model");
  const { withTransaction } = require("../models/MasterModule");
  const r = await login(OTHER); const cookie = cookieOf(r);
  assert.equal((await api("GET", "/api/auth/session", { cookie })).json.data.user.role, "OTHER");
  await withTransaction((tx) => UserModel.setRole(ids.other, ROLE.EMPLOYEE, tx));
  const after = await api("GET", "/api/auth/session", { cookie });
  assert.equal(after.json.data.user.role, "EMPLOYEE");
  assert.equal(after.json.data.permissionsRefreshed, true);
  assert.equal((await api("GET", "/api/auth/session", { cookie })).json.data.permissionsRefreshed, false);
  await withTransaction((tx) => UserModel.setRole(ids.other, ROLE.OTHER, tx)); // restore
});

test("the database refuses a user without a role or with an unknown role", async () => {
  const insert = (roleId) => query(
    `INSERT INTO auth.users (branch_id, name, username, password_hash, role_id) VALUES ((SELECT min(branch_id) FROM auth.branches), 'x', '__t_norole__', 'x', $1)`, [roleId]);
  await assert.rejects(insert(null), /null value in column "role_id"/);
  await assert.rejects(insert(99), /violates foreign key/);
});
