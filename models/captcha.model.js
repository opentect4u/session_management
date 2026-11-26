const { f_insert, f_delete } = require("./MasterModule");
const { sha256Hex } = require("../utils/crypto");

const hashAnswer = (id, answer) => sha256Hex(`${id}:${String(answer).trim().toUpperCase()}`);

const create = (id, answer, ttlMs) =>
  f_insert("auth.captcha_challenges", "(id, answer_hash, expires_at)", "($1, $2, now() + ($3 * interval '1 millisecond'))", "", 0, [id, hashAnswer(id, answer), ttlMs]);

/** Single use: the challenge is deleted whether the answer is right or wrong. True only if it was fresh and correct. */
const consume = async (id, answer) => {
  const r = await f_delete(null, "", [id], null,
    "DELETE FROM auth.captcha_challenges WHERE id = $1 RETURNING answer_hash, expires_at > now() AS fresh");
  if (!r.rows[0] || !r.rows[0].fresh) return false;
  return r.rows[0].answer_hash === hashAnswer(id, answer);
};

const deleteExpired = async () => (await f_delete("auth.captcha_challenges", "expires_at < now()")).rowCount;

module.exports = { create, consume, deleteExpired };
