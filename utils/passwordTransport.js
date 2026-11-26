/**
 * Transport encryption for passwords. The browser encrypts {password, ...} with the RSA public key
 * (RSA-OAEP, SHA-256); only this module holds the private key and decrypts it. The decrypted password is
 * used just to verify against the stored hash - stored passwords are hashed, never reversible.
 */
const { constants, createHash, createPrivateKey, createPublicKey, generateKeyPairSync, privateDecrypt } = require("node:crypto");
const config = require("../config");
const { badRequest } = require("./errors");

const { rsaPrivateKey, rsaModulusBits, payloadMaxAgeMs, encryptionRequired } = config.auth.password;

let privateKey;
if (rsaPrivateKey) {
  privateKey = createPrivateKey(rsaPrivateKey);
} else if (config.isProd) {
  throw new Error("AUTH_RSA_PRIVATE_KEY is required in production");
} else {
  console.warn("[auth] AUTH_RSA_PRIVATE_KEY not set - using a temporary key (logins break after every restart)");
  privateKey = generateKeyPairSync("rsa", { modulusLength: rsaModulusBits }).privateKey;
}
const publicPem = createPublicKey(privateKey).export({ type: "spki", format: "pem" });
const keyId = createHash("sha256").update(publicPem).digest("hex").slice(0, 16);

const getPublicKey = () => ({ algorithm: "RSA-OAEP-SHA256", keyId, publicKey: publicPem });

/** Decrypt a base64 RSA-OAEP blob into the JSON payload and enforce its timestamp `t` (ms). */
function decryptPayload(encryptedBase64) {
  if (typeof encryptedBase64 !== "string" || !encryptedBase64) {
    throw badRequest("ENCRYPTION_REQUIRED", "Password must be sent encrypted.");
  }
  let payload;
  try {
    const plain = privateDecrypt(
      { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      Buffer.from(encryptedBase64, "base64"),
    );
    payload = JSON.parse(plain.toString("utf8"));
  } catch {
    throw badRequest("DECRYPTION_FAILED", "Could not read the encrypted password. Reload the page and try again.");
  }
  if (typeof payload.t !== "number" || Math.abs(Date.now() - payload.t) > payloadMaxAgeMs) {
    throw badRequest("PAYLOAD_EXPIRED", "The request expired. Please try again.");
  }
  return payload;
}

module.exports = { getPublicKey, decryptPayload, encryptionRequired };
