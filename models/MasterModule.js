/**
 * GLOBAL DATABASE FUNCTIONS (PostgreSQL). Every query in the backend goes through these three:
 *
 *   f_select(select, table_name, whr, order, params, tx, fullQuery)
 *   f_insert(table_name, fields, values, whr, flag, params, tx, fullSql)   flag 0 = INSERT, 1 = UPDATE
 *   f_delete(table_name, whr, params, tx, fullSql)
 *
 * Rules
 *  - Values are ALWAYS passed in `params` and referenced as $1, $2, ... Never put a value inside the SQL text.
 *  - There is no auto-commit. Every call runs inside an explicit transaction:
 *      * without `tx`  -> the call opens its own transaction, COMMITs on success, ROLLBACKs on error.
 *      * with `tx`     -> it joins your transaction; YOU commit once everything succeeded (see withTransaction).
 *  - Errors are thrown (never swallowed), so a failure always rolls the transaction back.
 *  - Success returns { suc: 1, rows, rowCount }.
 *  - `fullQuery` / `fullSql` is for statements the simple builders can't express (joins in UPDATE, ON CONFLICT,
 *    RETURNING, ...). It is still run through the same parameterised, transactional path.
 */
const { pool } = require("../config/db");

/** Open a transaction. Call tx.commit() when ALL steps succeeded, tx.rollback() on any failure. */
async function beginTransaction() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
  } catch (err) {
    client.release();
    throw err;
  }
  let finished = false;
  const finish = async (sql) => {
    if (finished) return;
    finished = true;
    try {
      await client.query(sql);
    } finally {
      client.release();
    }
  };
  return { client, commit: () => finish("COMMIT"), rollback: () => finish("ROLLBACK") };
}

/**
 * Run several steps as ONE transaction: `await withTransaction(async (tx) => { ...f_insert(..., tx)... })`.
 * Commits manually when the callback finishes; rolls back and rethrows if anything throws.
 */
async function withTransaction(fn) {
  const tx = await beginTransaction();
  try {
    const result = await fn(tx);
    await tx.commit();
    return result;
  } catch (err) {
    await tx.rollback().catch(() => {});
    throw err;
  }
}

async function run(sql, params, tx) {
  if (tx) return tx.client.query(sql, params);
  return withTransaction((own) => own.client.query(sql, params));
}

const wrap = (res) => ({ suc: 1, rows: res.rows, rowCount: res.rowCount });

/** SELECT. `table_name` may contain JOINs; `order` may hold ORDER BY / LIMIT / FOR UPDATE. */
const f_select = async (select, table_name, whr = "", order = "", params = [], tx = null, fullQuery = null) => {
  const sql = fullQuery || `SELECT ${select}${table_name ? ` FROM ${table_name}` : ""}${whr ? ` WHERE ${whr}` : ""}${order ? ` ${order}` : ""}`;
  return wrap(await run(sql, params, tx));
};

/**
 * INSERT (flag 0): INSERT INTO table_name <fields> VALUES <values>      e.g. fields "(a, b)", values "($1, $2)"
 * UPDATE (flag 1): UPDATE table_name SET <fields> WHERE <whr>            e.g. fields "a = $1, b = $2"
 */
const f_insert = async (table_name, fields, values, whr = "", flag = 0, params = [], tx = null, fullSql = null) => {
  let sql = fullSql;
  if (!sql) {
    if (flag > 0) {
      if (!whr) throw new Error("f_insert: refusing an UPDATE without a WHERE clause");
      sql = `UPDATE ${table_name} SET ${fields} WHERE ${whr}`;
    } else {
      sql = `INSERT INTO ${table_name} ${fields} VALUES ${values}`;
    }
  }
  return wrap(await run(sql, params, tx));
};

const f_delete = async (table_name, whr = "", params = [], tx = null, fullSql = null) => {
  if (!fullSql && !whr) throw new Error("f_delete: refusing a DELETE without a WHERE clause");
  return wrap(await run(fullSql || `DELETE FROM ${table_name} WHERE ${whr}`, params, tx));
};

module.exports = { f_select, f_insert, f_delete, beginTransaction, withTransaction };
