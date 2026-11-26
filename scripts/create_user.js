/**
 * Creates a user (and the first branch if none exists yet).
 * Usage: npm run user:create -- <username> <password> <ROLE_CODE> ["Full name"] [branchId]
 * e.g.   npm run user:create -- admin 'Admin@12345' SUPERADMIN "Main Admin"
 */
const { pool } = require("../config/db");
const config = require("../config");
const { hashPassword } = require("../utils/password");
const UserModel = require("../models/user.model");

(async () => {
  const [username, password, roleCode, name = username, branchArg] = process.argv.slice(2);
  if (!username || !password || !roleCode) throw new Error("usage: npm run user:create -- <username> <password> <ROLE_CODE> [name] [branchId]");
  if (!Object.values(config.roles).includes(roleCode)) throw new Error(`ROLE_CODE must be one of ${Object.values(config.roles).join(", ")}`);
  if (password.length < config.auth.password.newPasswordMinLength) throw new Error(`password must have at least ${config.auth.password.newPasswordMinLength} characters`);

  const role = (await pool.query("SELECT role_id FROM auth.roles WHERE role_code = $1", [roleCode])).rows[0];
  if (!role) throw new Error("roles are missing - run npm run db:migrate first");

  let branchId = branchArg ? Number(branchArg) : (await pool.query("SELECT branch_id FROM auth.branches ORDER BY branch_id LIMIT 1")).rows[0]?.branch_id;
  if (!branchId) {
    branchId = (await pool.query("INSERT INTO auth.branches (branch_name, branch_code) VALUES ('Head Office', 'HO') RETURNING branch_id")).rows[0].branch_id;
    console.log(`created branch "Head Office" (id ${branchId})`);
  }

  const id = await UserModel.create({ username, name, passwordHash: await hashPassword(password), roleId: role.role_id, branchId });
  console.log(`created user ${username} (id ${id}, role ${roleCode}, branch ${branchId})`);
  await pool.end();
})().catch((err) => { console.error("failed:", err.message); process.exit(1); });
