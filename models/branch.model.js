const { f_select } = require("./MasterModule");

const COLUMNS = "c.branch_id AS id, c.branch_name AS name, c.branch_code AS code";
const TABLE = "auth.branches c";
const ORDER = "ORDER BY c.sequence, c.branch_name";

/** Every branch (what a global user may choose from). */
const listAll = async (tx) => (await f_select(COLUMNS, TABLE, "", ORDER, [], tx)).rows;

/**
 * Branches one user is assigned to (auth.user_branches). Only a user with NO assignment rows falls back to their
 * own home branch, so removing an assignment really removes access.
 */
const listForUser = async (userId, tx) =>
  (await f_select(COLUMNS, TABLE,
    `c.branch_id IN (SELECT branch_id FROM auth.user_branches WHERE user_id = $1)
     OR (NOT EXISTS (SELECT 1 FROM auth.user_branches WHERE user_id = $1)
         AND c.branch_id = (SELECT branch_id FROM auth.users WHERE user_id = $1))`,
    ORDER, [userId], tx)).rows;

const findById = async (id, tx) => (await f_select(COLUMNS, TABLE, "c.branch_id = $1", "", [id], tx)).rows[0] || null;

module.exports = { listAll, listForUser, findById };
