/**
 * Branch-scope rules. The scope is decided HERE, on the server, from the user's role and branch assignments:
 * the browser only asks, it can never grant itself a branch or the global view.
 */
const config = require("../config");
const Branch = require("../models/branch.model");
const SessionModel = require("../models/session.model");
const History = require("../models/loginHistory.model");
const { badRequest, forbidden } = require("../utils/errors");
const { withTransaction } = require("../models/MasterModule");

const { scope: S, events } = config;

/** What this user may choose: { canGlobal, branches }. */
async function optionsFor(user) {
  const canGlobal = S.globalRoles.includes(user.role);
  const branches = canGlobal ? await Branch.listAll() : await Branch.listForUser(user.id);
  return { canGlobal, branches };
}

/** Scope chosen automatically at login, or null when the user must pick. */
function initialScope(user, options) {
  if (S.alwaysChooseRoles.includes(user.role)) return null;
  if (!options.canGlobal && options.branches.length === 1) return { mode: S.BRANCH, branchId: options.branches[0].id };
  return null;
}

/** Check a requested { mode, branchId } against what the user may use. Returns the clean scope or throws. */
function validate(input, options) {
  const mode = input?.mode;
  if (mode === S.GLOBAL) {
    if (!options.canGlobal) throw forbidden("SCOPE_FORBIDDEN", "You are not allowed to work in global mode.");
    return { mode: S.GLOBAL, branchId: null };
  }
  if (mode === S.BRANCH) {
    const branchId = Number(input.branchId);
    if (!Number.isInteger(branchId) || branchId <= 0) throw badRequest("VALIDATION_ERROR", "Choose a branch.");
    if (!options.branches.some((b) => b.id === branchId)) throw forbidden("SCOPE_FORBIDDEN", "You are not assigned to that branch.");
    return { mode: S.BRANCH, branchId };
  }
  throw badRequest("VALIDATION_ERROR", `mode must be ${S.GLOBAL} or ${S.BRANCH}.`);
}

/** Is a scope stored on a session still allowed (e.g. after the admin removed the user from that branch)? */
const stillAllowed = async (user, scope) => {
  try { validate(scope, await optionsFor(user)); return true; } catch { return false; }
};

/** The user picks / switches scope. Validated, stored on the session and audited in one transaction. */
async function select(auth, input, client) {
  const options = await optionsFor(auth.user);
  const scope = validate(input, options);
  const branch = scope.mode === S.BRANCH ? options.branches.find((b) => b.id === scope.branchId) : null;
  await withTransaction(async (tx) => {
    if (!(await SessionModel.setScope(auth.sessionHash, scope, tx))) throw badRequest("SESSION_REVOKED", "Your session has ended.");
    await History.record({ userId: auth.user.id, event: events.SCOPE_SELECTED, reason: scope.mode === S.GLOBAL ? S.GLOBAL : `${S.BRANCH}:${scope.branchId}`, ...client }, tx);
  });
  return { mode: scope.mode, branchId: scope.branchId, branchName: branch?.name ?? null };
}

module.exports = { optionsFor, initialScope, validate, stillAllowed, select };
