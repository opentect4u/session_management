/**
 * GLOBAL CONFIGURATION - the single place for every tunable value of the auth service.
 * Change a number here (or override it with the env var shown beside it) and the whole service follows.
 */
require("dotenv").config();

const num = (value, fallback) => (value !== undefined && value !== "" && !Number.isNaN(Number(value)) ? Number(value) : fallback);
const bool = (value, fallback) => (value === undefined || value === "" ? fallback : ["1", "true", "yes"].includes(String(value).toLowerCase()));

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;

const env = process.env.NODE_ENV || "development";
const isProd = env === "production";

module.exports = {
  env,
  isProd,

  server: {
    port: num(process.env.PORT, 3001),
    /** Number of reverse proxies in front of the app (0 = none). Needed for a correct client IP. */
    trustProxy: num(process.env.TRUST_PROXY, 0),
    jsonBodyLimit: "10kb",
    /** Must be longer than any proxy's idle timeout, otherwise proxies reuse a connection the server just closed (ECONNRESET). */
    keepAliveTimeoutMs: num(process.env.SERVER_KEEP_ALIVE_SEC, 65) * SECOND,
  },

  db: {
    host: process.env.PG_HOST,
    port: num(process.env.PG_PORT, 5432),
    user: process.env.PG_USER,
    password: process.env.PG_PASSWORD,
    database: process.env.PG_DATABASE,
    ssl: bool(process.env.PG_SSL, false),
    poolMax: num(process.env.PG_POOL_MAX, 10),
  },

  auth: {
    /** Roles allowed to unlock a locked account. */
    unlockRoles: ["SUPERADMIN", "ADMIN"],

    /** Consecutive wrong passwords before the account is locked (an admin must unlock). */
    maxFailedAttempts: num(process.env.AUTH_MAX_FAILED_ATTEMPTS, 5),

    /** "replace" = a new login signs the old device out, "deny" = a second login is refused. */
    singleSessionPolicy: process.env.AUTH_SINGLE_SESSION_POLICY || "replace",

    session: {
      idleTimeoutMs: num(process.env.AUTH_IDLE_TIMEOUT_MIN, 20) * MINUTE, // inactivity limit
      absoluteTimeoutMs: num(process.env.AUTH_ABSOLUTE_TIMEOUT_HOURS, 8) * HOUR, // hard limit
      touchIntervalMs: num(process.env.AUTH_TOUCH_INTERVAL_SEC, 60) * SECOND, // last_seen_at is written at most this often
      cleanupIntervalMs: num(process.env.AUTH_CLEANUP_INTERVAL_MIN, 15) * MINUTE,
      revokedRetentionMs: num(process.env.AUTH_REVOKED_RETENTION_MIN, 60) * MINUTE, // keep revoked rows briefly so the old device learns why
      idBytes: 32, // 256-bit session id
      csrfBytes: 32,
    },

    cookie: {
      // "__Host-" prefix = the browser enforces Secure + Path=/ + no Domain (production only; needs HTTPS)
      name: isProd ? "__Host-jkt_sid" : "jkt_sid",
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      path: "/",
    },

    csrf: {
      headerName: "x-csrf-token",
      safeMethods: ["GET", "HEAD", "OPTIONS"],
    },

    captcha: {
      length: 5,
      ttlMs: num(process.env.AUTH_CAPTCHA_TTL_MIN, 3) * MINUTE,
      alphabet: "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", // no look-alikes (0/O, 1/I)
      width: 160,
      height: 48,
    },

    password: {
      /** Passwords must arrive RSA-encrypted; plain-text login requests are refused. */
      encryptionRequired: bool(process.env.AUTH_PASSWORD_ENCRYPTION_REQUIRED, true),
      /** PEM private key (use \n for newlines in .env). Dev: generated at start-up if empty. Production: required. */
      rsaPrivateKey: (process.env.AUTH_RSA_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
      rsaModulusBits: 2048,
      payloadMaxAgeMs: 2 * MINUTE, // an encrypted payload older than this is rejected (anti-replay)
      maxLength: 100, // keeps the payload inside RSA-OAEP's size limit
      newPasswordMinLength: 8,
      scrypt: { N: 16384, r: 8, p: 1, keyLength: 64, saltBytes: 16 },
    },

    rateLimit: {
      // per IP, in-memory; protects the login/captcha endpoints from floods
      windowMs: num(process.env.AUTH_RATE_WINDOW_MIN, 10) * MINUTE,
      loginMax: num(process.env.AUTH_RATE_LOGIN_MAX, 30),
      captchaMax: num(process.env.AUTH_RATE_CAPTCHA_MAX, 60),
    },
  },

  /** The four application roles (codes in auth.roles.role_code). Use these constants, never string literals. */
  roles: {
    SUPERADMIN: "SUPERADMIN",
    ADMIN: "ADMIN",
    EMPLOYEE: "EMPLOYEE",
    OTHER: "OTHER",
  },

  /**
   * Branch scope. After login the user works GLOBALLY or inside ONE branch (a row of auth.branches),
   * and every list / report is meant to be filtered by that choice until they switch (see utils/scope.js).
   */
  scope: {
    GLOBAL: "GLOBAL",
    BRANCH: "BRANCH",
    /** Roles that may work in global mode (and see every branch). */
    globalRoles: ["SUPERADMIN"],
    /** Roles that always see the chooser after login, even if only one branch exists. Everyone else with exactly one branch goes straight in. */
    alwaysChooseRoles: ["SUPERADMIN"],
    /** branch id stored on a record to mean "global" (visible in every branch). Real branches must never use this id. */
    globalBranchId: 0,
  },

  /** Event names written to auth.login_history. */
  events: {
    LOGIN_SUCCESS: "LOGIN_SUCCESS",
    LOGIN_FAILED: "LOGIN_FAILED",
    LOGIN_BLOCKED: "LOGIN_BLOCKED",
    CAPTCHA_FAILED: "CAPTCHA_FAILED",
    ACCOUNT_LOCKED: "ACCOUNT_LOCKED",
    ACCOUNT_UNLOCKED: "ACCOUNT_UNLOCKED",
    SESSION_REPLACED: "SESSION_REPLACED",
    LOGOUT: "LOGOUT",
    PASSWORD_CHANGED: "PASSWORD_CHANGED",
    SCOPE_SELECTED: "SCOPE_SELECTED",
  },

  /** Reasons stored in auth.sessions.revoke_reason. */
  revokeReasons: {
    LOGOUT: "LOGOUT",
    NEW_LOGIN: "NEW_LOGIN",
    PASSWORD_CHANGED: "PASSWORD_CHANGED",
    USER_DEACTIVATED: "USER_DEACTIVATED",
    ACCOUNT_LOCKED: "ACCOUNT_LOCKED",
  },
};
