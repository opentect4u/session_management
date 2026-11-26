const { randomBytes, scrypt } = require("node:crypto");
const { promisify } = require("node:util");
const config = require("../config");
const { safeEqual } = require("./crypto");

const scryptAsync = promisify(scrypt);
const P = config.auth.password.scrypt;

/** scrypt hash in the form scrypt$N$r$p$salt$hash (all params stored, so they can be raised later). */
async function hashPassword(plain) {
  const salt = randomBytes(P.saltBytes);
  const key = await scryptAsync(plain, salt, P.keyLength, { N: P.N, r: P.r, p: P.p, maxmem: 128 * P.N * P.r * 2 });
  return ["scrypt", P.N, P.r, P.p, salt.toString("base64"), key.toString("base64")].join("$");
}

async function verifyScrypt(plain, stored) {
  const [, N, r, p, salt, hash] = String(stored).split("$");
  const expected = Buffer.from(hash, "base64");
  const key = await scryptAsync(plain, Buffer.from(salt, "base64"), expected.length, { N: +N, r: +r, p: +p, maxmem: 128 * +N * +r * 2 });
  return safeEqual(key.toString("base64"), hash);
}

let dummyHash;
/** Burn the same time as a real check so "unknown user" and "wrong password" cannot be told apart by timing. */
async function burnTime(plain) {
  dummyHash ??= await hashPassword(randomBytes(8).toString("hex"));
  await verifyScrypt(plain, dummyHash);
}

module.exports = { hashPassword, verifyScrypt, burnTime };
