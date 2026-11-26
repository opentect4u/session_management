# Auth Service

Standalone extraction of the login, session management, CSRF protection, captcha, audit trail and branch-scope code of the JK Travels backend.
Node.js (CommonJS) + Express 5 + PostgreSQL (`pg`, no ORM).

## Quick start

```bash
npm install
cp .env.example .env          # fill in PG_* ; AUTH_RSA_PRIVATE_KEY is required in production
npm run db:migrate            # applies db/postgres/schema.sql (idempotent)
npm run user:create -- admin 'Admin@12345' SUPERADMIN "Main Admin"
npm run dev                   # http://localhost:3001/api/health
AUTH_RATE_LOGIN_MAX=1000 npm test   # integration tests against the real DB from .env (create + delete their own rows)
```

## Database files

| File | Purpose |
|---|---|
| [db/postgres/schema.sql](db/postgres/schema.sql) | Table structure used by the Node code (schema `auth`). |
| [db/mysql/auth_service_dump.sql](db/mysql/auth_service_dump.sql) | Same structure translated to MySQL 8.0.16+ (structure + roles + one branch). Plain table names, no schema. The Node code does **not** use MySQL. |

Tables: `roles`, `branches`, `users`, `user_branches` (supporting tables standing in for the main app's employee / branch masters) and the session tables
`user_security`, `sessions`, `login_history`, `captcha_challenges`.
If you plug this into another application, replace `users` / `branches` with your own tables and adjust `models/user.model.js`, `models/session.model.js` and `models/branch.model.js` (the only files that know their names).

## How it works

- **Login** (`POST /api/auth/login`): captcha is checked first (single use) → password arrives **RSA-OAEP encrypted** (`GET /api/auth/public-key`) in a payload `{ p: password, c: captchaId, t: timestamp }` bound to that captcha and valid for 2 minutes → user checks (same generic error for unknown / inactive users) → scrypt password check → wrong passwords are counted and the account locks at `maxFailedAttempts` (an admin must unlock) → session is created in one transaction.
- **Session**: random 256-bit id in an httpOnly cookie (`jkt_sid`, `__Host-jkt_sid` in production). Only its SHA-256 is stored (`auth.sessions.session_id_hash`). Idle timeout (20 min, extended on activity, `last_seen_at` written at most once a minute) and absolute timeout (8 h). Single-session policy: a new login signs the old device out (`replace`) or is refused (`deny`). Logout, password change, deactivation and lock revoke sessions; the old device learns the reason (`revoke_reason`).
- **Every request** ([middleware/authenticate.js](middleware/authenticate.js)): one primary-key lookup, rejects revoked / expired sessions and deactivated or locked users, syncs `permission_version` (rights changes apply on the very next request) and sets `req.auth`.
- **CSRF** ([middleware/csrf.js](middleware/csrf.js)): each session has a `csrf_token`, returned by login and `GET /api/auth/session`. Every non-GET request must send it in the `X-CSRF-Token` header (constant-time compare). Use `authenticate` before `csrfProtection`.
- **Branch scope**: after login the user works GLOBAL (Superadmin only) or in one branch, stored on the session (`scope_mode`, `scope_branch_id`). Data routes use `authenticate, requireScope` and apply the scope with [utils/scope.js](utils/scope.js). Delete this layer if you don't need branches (also the `scope_*` columns).
- **Audit**: every event goes to `auth.login_history`, which the cleanup job ([jobs/sessionCleanup.js](jobs/sessionCleanup.js)) never deletes.
- All tunables (timeouts, limits, roles, event names) live in [config/index.js](config/index.js).

## API (all under `/api/auth`)

| Method & path | Auth | Notes |
|---|---|---|
| `GET /public-key` | – | RSA public key (PEM) for password encryption |
| `GET /captcha` | – | `{ captchaId, image (SVG data-URI), expiresInSeconds }`; rate limited |
| `POST /login` | – | `{ username, captchaId, captchaAnswer, encryptedPassword }`; rate limited. Sets the cookie; returns `user`, `csrfToken`, expiry times, `scope`, `scopeOptions` |
| `GET /session` | cookie | Who am I; also how the SPA gets the CSRF token after a reload |
| `PUT /scope` | cookie + CSRF | `{ mode: "GLOBAL" }` or `{ mode: "BRANCH", branchId }` |
| `POST /logout` | cookie + CSRF | Signs out of every device |
| `POST /change-password` | cookie + CSRF | `{ encryptedPayload }` = RSA of `{ cp, np, t }`; revokes all sessions |
| `POST /users/:id/unlock` | cookie + CSRF + role SUPERADMIN/ADMIN | Clears the lock |

Errors: `{ success: false, error: { code, message, ... } }`; success: `{ success: true, data }`. Notable codes: `UNAUTHENTICATED`, `SESSION_REVOKED` / `SESSION_EXPIRED` (with `reason`), `CSRF_INVALID`, `CAPTCHA_INVALID`, `INVALID_CREDENTIALS` (with `attemptsRemaining`), `ACCOUNT_LOCKED` (423), `SCOPE_REQUIRED`.

### Browser side: encrypting the password

```js
const { data } = await (await fetch("/api/auth/public-key")).json();
const der = Uint8Array.from(atob(data.publicKey.replace(/-----[^-]+-----|\s/g, "")), (c) => c.charCodeAt(0));
const key = await crypto.subtle.importKey("spki", der, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
const payload = new TextEncoder().encode(JSON.stringify({ p: password, c: captchaId, t: Date.now() }));
const encryptedPassword = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, payload))));
```

Send requests with `credentials: "include"` (or same-origin) and the `X-CSRF-Token` header on every POST / PUT / DELETE.

## Adding a protected module

```js
router.use(authenticate, requireScope, requireRole("ADMIN"));   // session + chosen branch + role
router.post("/", csrfProtection, ctrl.create);                  // state-changing routes also need CSRF
```
Register the router in [routes/index.js](routes/index.js). Throw `AppError` helpers from [utils/errors.js](utils/errors.js) for client-safe errors.

## Notes

- The in-memory rate limiter ([middleware/rateLimit.js](middleware/rateLimit.js)) is per process; with several instances move the counters to Redis / the DB.
- Without `AUTH_RSA_PRIVATE_KEY` a temporary key is generated in development, so logins break after each restart.
- Differences from the original backend: no legacy MD5 password path (passwords are always scrypt, in `users.password_hash`), `users.is_active` / `login_allowed` booleans replace the legacy `'1'/'0'` status columns, and the original `/roles` route and employee/branch masters were left out.
