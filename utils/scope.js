/**
 * Helpers every data module uses so the user's branch scope is applied the SAME way everywhere.
 * (req.auth.scope is set by authenticate; routes that call these must also use middleware/requireScope.)
 *
 *   READ   const f = scopeFilter(req, "b.branch_id", { firstParam: 2 });  // transactional data: bookings, invoices, reports
 *          f_select("*", "td_booking_details b", `b.status = $1 AND ${f.sql}`, "", ["1", ...f.params])   // other params first -> pass { firstParam: 2 }
 *   MASTER const f = scopeFilter(req, "branch_id", { includeGlobal: true });   // branch rows + global rows
 *   WRITE  const branchId = await resolveWriteBranch(req, req.body.branchId, { allowGlobal: true });
 *
 * A record's branch is its branch_id column; the id config.scope.globalBranchId (0) marks a "global" master record.
 */
const config = require("../config");
const Branch = require("../models/branch.model");
const { badRequest, forbidden } = require("./errors");

const { scope: S } = config;

/**
 * SQL condition + params for the user's scope. `firstParam` is the number of the first placeholder to use ($n),
 * so the fragment can be appended to a query that already has parameters.
 *   global mode           -> no restriction ("TRUE")
 *   branch mode           -> column = $n
 *   branch + includeGlobal-> (column = $n OR column = $n+1)   [the branch's own rows plus global master rows]
 */
function scopeFilter(req, column, { includeGlobal = false, firstParam = 1 } = {}) {
  const scope = req.auth?.scope;
  if (!scope) throw forbidden("SCOPE_REQUIRED", "Choose a branch (or global view) before continuing.");
  if (scope.mode === S.GLOBAL) return { sql: "TRUE", params: [] };
  if (includeGlobal) return { sql: `(${column} = $${firstParam} OR ${column} = $${firstParam + 1})`, params: [scope.branchId, S.globalBranchId] };
  return { sql: `${column} = $${firstParam}`, params: [scope.branchId] };
}

/**
 * The branch_id to store on a new/edited record.
 *  - branch mode: always the active branch; a global record cannot be created and the client's value is ignored.
 *  - global mode: the caller must say where it goes: a real branch id, or (when allowGlobal) the global id.
 */
async function resolveWriteBranch(req, requested, { allowGlobal = false } = {}) {
  const scope = req.auth?.scope;
  if (!scope) throw forbidden("SCOPE_REQUIRED", "Choose a branch (or global view) before continuing.");
  if (scope.mode === S.BRANCH) return scope.branchId;

  if (requested === undefined || requested === null || requested === "") throw badRequest("VALIDATION_ERROR", allowGlobal ? "Choose a branch or Global for this record." : "Choose a branch for this record.");
  const id = Number(requested);
  if (!Number.isInteger(id) || id < 0) throw badRequest("VALIDATION_ERROR", "Invalid branch.");
  if (id === S.globalBranchId) {
    if (!allowGlobal) throw badRequest("VALIDATION_ERROR", "This record must belong to a branch.");
    return id;
  }
  if (!(await Branch.findById(id))) throw badRequest("VALIDATION_ERROR", "Unknown branch.");
  return id;
}

/**
 * Like scopeFilter, for rows that belong to branches through a link table (a user is attached to many branches):
 *   global mode -> TRUE;   branch mode -> EXISTS (a link row between this row and the active branch).
 * `rowKey` is the row's id column in the main query (e.g. "u.user_id").
 */
function scopeFilterViaLink(req, rowKey, { linkTable = "auth.user_branches", linkOwner = "user_id", linkBranch = "branch_id", firstParam = 1 } = {}) {
  const scope = req.auth?.scope;
  if (!scope) throw forbidden("SCOPE_REQUIRED", "Choose a branch (or global view) before continuing.");
  if (scope.mode === S.GLOBAL) return { sql: "TRUE", params: [] };
  return { sql: `EXISTS (SELECT 1 FROM ${linkTable} sl WHERE sl.${linkOwner} = ${rowKey} AND sl.${linkBranch} = $${firstParam})`, params: [scope.branchId] };
}

module.exports = { scopeFilter, scopeFilterViaLink, resolveWriteBranch };
