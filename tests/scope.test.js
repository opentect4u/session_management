/**
 * Branch-scope tests against the real Postgres. Creates two temporary branches (ids 9001/9002) and four temporary users,
 * and removes everything afterwards. Run: AUTH_RATE_LOGIN_MAX=1000 npm test
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const { createHash, publicEncrypt, constants, randomUUID } = require("node:crypto");
const app = require("../app");
const { pool } = require("../config/db");
const CaptchaModel = require("../models/captcha.model");
const { hashPassword } = require("../utils/password");
const { scopeFilter, resolveWriteBranch } = require("../utils/scope");

const query = (text, params) => pool.query(text, params);
const B1 = 9001, B2 = 9002;
const PW = "Scope@12345";
const U = { super: "__s_super__", multi: "__s_multi__", one: "__s_one__", none: "__s_none__" };
const ROLE = { SUPERADMIN: 1, ADMIN: 2, EMPLOYEE: 3 };
let base, server, publicKey; const ids = {};

async function api(method, path, { body, cookie, csrf } = {}) {
  const res = await fetch(base + path, { method, headers: { "content-type": "application/json", ...(cookie && { cookie }), ...(csrf && { "x-csrf-token": csrf }) }, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, json: await res.json(), setCookie: res.headers.get("set-cookie") };
}
const encrypt = (obj) => publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.from(JSON.stringify({ ...obj, t: Date.now() }))).toString("base64");
async function login(username) {
  const captchaId = randomUUID(); await CaptchaModel.create(captchaId, "ABCDE", 60000);
  const r = await api("POST", "/api/auth/login", { body: { username, captchaId, captchaAnswer: "abcde", encryptedPassword: encrypt({ p: PW, c: captchaId }) } });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  return { data: r.json.data, cookie: r.setCookie.split(";")[0], csrf: r.json.data.csrfToken };
}
async function employee(username, roleId) {
  const { rows } = await query(
    `INSERT INTO auth.users (branch_id, name, username, password_hash, role_id) VALUES (1, $1, $1, $2, $3) RETURNING user_id`,
    [username, await hashPassword(PW), roleId]);
  return rows[0].user_id;
}
const assign = (empId, branchId) => query("INSERT INTO auth.user_branches (user_id, branch_id) VALUES ($1,$2)", [empId, branchId]);
const reqWith = (scope) => ({ auth: { scope } });

test.before(async () => {
  await new Promise((r) => { server = app.listen(0, () => { base = `http://127.0.0.1:${server.address().port}`; r(); }); });
  publicKey = (await api("GET", "/api/auth/public-key")).json.data.publicKey;
  for (const id of [B1, B2]) {
    await query("INSERT INTO auth.branches (branch_id, branch_name, branch_code, sequence) VALUES ($1,$2,$3,99)", [id, `__t_branch_${id}`, `T${id}`]);
  }
  ids.super = await employee(U.super, ROLE.SUPERADMIN);
  ids.multi = await employee(U.multi, ROLE.ADMIN);   await assign(ids.multi, B1); await assign(ids.multi, B2);
  ids.one = await employee(U.one, ROLE.EMPLOYEE);    await assign(ids.one, B1);
  ids.none = await employee(U.none, ROLE.EMPLOYEE);  // no assignment rows -> falls back to home branch 1
});

test.after(async () => {
  const list = Object.values(ids);
  await query("DELETE FROM auth.user_branches WHERE user_id = ANY($1)", [list]);
  await query("DELETE FROM auth.users WHERE user_id = ANY($1)", [list]);
  await query("DELETE FROM auth.login_history WHERE user_id = ANY($1) OR username = ANY($2)", [list, Object.values(U)]);
  await query("DELETE FROM auth.branches WHERE branch_id = ANY($1)", [[B1, B2]]);
  server.close(); await pool.end();
});

test("user with exactly one branch goes straight into it", async () => {
  const s = await login(U.one);
  assert.deepEqual([s.data.scope.mode, s.data.scope.branchId, s.data.scope.branchName], ["BRANCH", B1, `__t_branch_${B1}`]);
  assert.equal(s.data.scopeOptions.canGlobal, false);
  assert.deepEqual(s.data.scopeOptions.branches.map((b) => b.id), [B1]);
});

test("user without assignment rows falls back to their home branch", async () => {
  const s = await login(U.none);
  assert.equal(s.data.scope.branchId, 1);
});

test("Superadmin always sees the chooser, with global + every branch", async () => {
  const s = await login(U.super);
  assert.equal(s.data.scope, null);
  assert.equal(s.data.scopeOptions.canGlobal, true);
  const got = s.data.scopeOptions.branches.map((b) => b.id);
  assert.ok(got.includes(B1) && got.includes(B2) && got.includes(1));
  assert.equal((await api("GET", "/api/auth/session", { cookie: s.cookie })).json.data.scope, null, "still unchosen after a reload");
});

test("multi-branch admin must choose, and only among assigned branches (no global)", async () => {
  const s = await login(U.multi);
  assert.equal(s.data.scope, null);
  assert.deepEqual(s.data.scopeOptions.branches.map((b) => b.id).sort(), [B1, B2]);
  const h = { cookie: s.cookie, csrf: s.csrf };
  assert.equal((await api("PUT", "/api/auth/scope", { ...h, body: { mode: "GLOBAL" } })).json.error.code, "SCOPE_FORBIDDEN");
  assert.equal((await api("PUT", "/api/auth/scope", { ...h, body: { mode: "BRANCH", branchId: 1 } })).json.error.code, "SCOPE_FORBIDDEN");
  assert.equal((await api("PUT", "/api/auth/scope", { ...h, body: { mode: "BRANCH", branchId: "x" } })).status, 400);
  assert.equal((await api("PUT", "/api/auth/scope", { cookie: s.cookie, body: { mode: "BRANCH", branchId: B1 } })).status, 403, "CSRF required");
  const ok = await api("PUT", "/api/auth/scope", { ...h, body: { mode: "BRANCH", branchId: B2 } });
  assert.equal(ok.json.data.scope.branchId, B2);
  assert.equal((await api("GET", "/api/auth/session", { cookie: s.cookie })).json.data.scope.branchId, B2, "persisted on the session");
});

test("Superadmin can switch global <-> branch any time", async () => {
  const s = await login(U.super); const h = { cookie: s.cookie, csrf: s.csrf };
  assert.equal((await api("PUT", "/api/auth/scope", { ...h, body: { mode: "GLOBAL" } })).json.data.scope.mode, "GLOBAL");
  assert.equal((await api("PUT", "/api/auth/scope", { ...h, body: { mode: "BRANCH", branchId: B1 } })).json.data.scope.branchId, B1);
  assert.equal((await api("PUT", "/api/auth/scope", { ...h, body: { mode: "GLOBAL" } })).json.data.scope.branchName, null);
  const { rows } = await query("SELECT reason FROM auth.login_history WHERE user_id=$1 AND event='SCOPE_SELECTED' ORDER BY id", [ids.super]);
  assert.deepEqual(rows.map((r) => r.reason), ["GLOBAL", `BRANCH:${B1}`, "GLOBAL"], "every switch is audited");
});

test("removing a branch assignment sends the user back to the chooser after a permission bump", async () => {
  const s = await login(U.multi); const h = { cookie: s.cookie, csrf: s.csrf };
  await api("PUT", "/api/auth/scope", { ...h, body: { mode: "BRANCH", branchId: B2 } });
  await query("DELETE FROM auth.user_branches WHERE user_id=$1 AND branch_id=$2", [ids.multi, B2]);
  await query("INSERT INTO auth.user_security (user_id) VALUES ($1) ON CONFLICT (user_id) DO UPDATE SET permission_version = auth.user_security.permission_version + 1", [ids.multi]);
  const after = await api("GET", "/api/auth/session", { cookie: s.cookie });
  assert.equal(after.json.data.scope, null);
  assert.deepEqual(after.json.data.scopeOptions.branches.map((b) => b.id), [B1]);
});

test("scopeFilter / resolveWriteBranch apply the scope the same way everywhere", async () => {
  const glob = reqWith({ mode: "GLOBAL", branchId: null }), br = reqWith({ mode: "BRANCH", branchId: B1 });
  assert.deepEqual(scopeFilter(glob, "b.branch_id"), { sql: "TRUE", params: [] });
  assert.deepEqual(scopeFilter(br, "b.branch_id"), { sql: "b.branch_id = $1", params: [B1] });
  assert.deepEqual(scopeFilter(br, "c", { includeGlobal: true, firstParam: 3 }), { sql: "(c = $3 OR c = $4)", params: [B1, 0] });
  assert.throws(() => scopeFilter(reqWith(null), "c"), { code: "SCOPE_REQUIRED" });

  assert.equal(await resolveWriteBranch(br, 12345, { allowGlobal: true }), B1, "branch user can only write to their branch");
  assert.equal(await resolveWriteBranch(br, 0, { allowGlobal: true }), B1, "...and can never create a global record");
  assert.equal(await resolveWriteBranch(glob, B2), B2);
  assert.equal(await resolveWriteBranch(glob, 0, { allowGlobal: true }), 0);
  await assert.rejects(resolveWriteBranch(glob, 0), { code: "VALIDATION_ERROR" });
  await assert.rejects(resolveWriteBranch(glob, undefined, { allowGlobal: true }), { code: "VALIDATION_ERROR" });
  await assert.rejects(resolveWriteBranch(glob, 777777), { code: "VALIDATION_ERROR" });
});
