-- =====================================================================================================================
-- AUTH SERVICE - MySQL dump (structure + reference data) of the login / session / CSRF / captcha / audit tables.
-- Same tables and columns as db/postgres/schema.sql, translated to MySQL 8.0.16+ (InnoDB, utf8mb4).
--
-- Import:   mysql -u <user> -p <database> < db/mysql/auth_service_dump.sql
--           (or create a database first:  CREATE DATABASE auth_service CHARACTER SET utf8mb4;  then import into it)
--
-- Differences from the PostgreSQL version
--   * Postgres schema "auth" -> plain table names in the chosen database (MySQL has no schemas); table names stay identical.
--   * timestamptz -> DATETIME(3). Store and compare ALL times in UTC (the Node service writes UTC).
--   * jsonb -> JSON, uuid -> CHAR(36), boolean -> TINYINT(1), identity -> AUTO_INCREMENT.
--   * The partial index on sessions (WHERE revoked_at IS NULL) does not exist in MySQL -> a normal index on (user_id, revoked_at).
--   * CHECK constraints are enforced from MySQL 8.0.16 (older versions parse and silently ignore them).
-- NOTE: the Node code in this repository talks to PostgreSQL. This dump is the structure to use when the sessions
--       are implemented on a MySQL stack; the logic (hash of session id, CSRF token, lock counters ...) is documented in the README.
-- =====================================================================================================================
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8mb4 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;

-- ---------------------------------------------------------------- drop (children first)
DROP TABLE IF EXISTS `captcha_challenges`;
DROP TABLE IF EXISTS `login_history`;
DROP TABLE IF EXISTS `sessions`;
DROP TABLE IF EXISTS `user_security`;
DROP TABLE IF EXISTS `user_branches`;
DROP TABLE IF EXISTS `users`;
DROP TABLE IF EXISTS `branches`;
DROP TABLE IF EXISTS `roles`;

-- ---------------------------------------------------------------- roles: role master
CREATE TABLE `roles` (
  `role_id`         SMALLINT     NOT NULL,
  `role_code`       VARCHAR(20)  NOT NULL COMMENT 'stable code used in code/config: SUPERADMIN | ADMIN | EMPLOYEE | OTHER',
  `role_name`       VARCHAR(50)  NOT NULL COMMENT 'label shown to people',
  `hierarchy_level` SMALLINT     NOT NULL COMMENT '1 = most powerful; for "can manage someone of a lower level" checks',
  PRIMARY KEY (`role_id`),
  UNIQUE KEY `roles_role_code_uq` (`role_code`),
  UNIQUE KEY `roles_hierarchy_level_uq` (`hierarchy_level`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------- branches
CREATE TABLE `branches` (
  `branch_id`   INT          NOT NULL AUTO_INCREMENT COMMENT 'id 0 is reserved to mean "global"',
  `branch_name` VARCHAR(100) NOT NULL,
  `branch_code` VARCHAR(10)  NOT NULL,
  `sequence`    INT          NOT NULL DEFAULT 0 COMMENT 'display order',
  PRIMARY KEY (`branch_id`),
  UNIQUE KEY `branches_branch_code_uq` (`branch_code`),
  CONSTRAINT `branches_id_positive_chk` CHECK (`branch_id` > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------- users: the people who can log in
CREATE TABLE `users` (
  `user_id`       INT          NOT NULL AUTO_INCREMENT,
  `branch_id`     INT          NOT NULL COMMENT 'home branch = tenant_id of the session',
  `username`      VARCHAR(50)  NOT NULL COMMENT 'login name',
  `name`          VARCHAR(100) NOT NULL,
  `password_hash` TEXT         NOT NULL COMMENT 'scrypt$N$r$p$salt$hash (never reversible)',
  `role_id`       SMALLINT     NOT NULL COMMENT 'no default: whoever creates a user must choose a role',
  `is_active`     TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '0 = deactivated (sessions die on the next request)',
  `login_allowed` TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '0 = may exist but may not sign in',
  `created_at`    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `users_username_uq` (`username`),
  KEY `users_branch_idx` (`branch_id`),
  KEY `users_role_idx` (`role_id`),
  CONSTRAINT `users_branch_fk` FOREIGN KEY (`branch_id`) REFERENCES `branches` (`branch_id`),
  CONSTRAINT `users_role_fk`   FOREIGN KEY (`role_id`)   REFERENCES `roles` (`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------- user_branches: branches a user may work in
-- A user with NO rows here falls back to their home branch.
CREATE TABLE `user_branches` (
  `user_branch_id` INT NOT NULL AUTO_INCREMENT,
  `user_id`        INT NOT NULL,
  `branch_id`      INT NOT NULL,
  PRIMARY KEY (`user_branch_id`),
  UNIQUE KEY `user_branches_unique` (`user_id`, `branch_id`),
  KEY `user_branches_branch_idx` (`branch_id`),
  CONSTRAINT `user_branches_user_fk`   FOREIGN KEY (`user_id`)   REFERENCES `users` (`user_id`) ON DELETE CASCADE,
  CONSTRAINT `user_branches_branch_fk` FOREIGN KEY (`branch_id`) REFERENCES `branches` (`branch_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------- user_security: per-user security state (row is created on first use)
CREATE TABLE `user_security` (
  `user_id`             INT         NOT NULL,
  `permission_version`  INT         NOT NULL DEFAULT 1 COMMENT 'bumped when rights change; live sessions adopt it on their next request',
  `failed_attempts`     INT         NOT NULL DEFAULT 0,
  `locked_at`           DATETIME(3) NULL COMMENT 'NOT NULL = locked, only an admin can unlock',
  `last_login_at`       DATETIME(3) NULL,
  `password_changed_at` DATETIME(3) NULL,
  PRIMARY KEY (`user_id`),
  CONSTRAINT `user_security_user_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------- sessions
CREATE TABLE `sessions` (
  `session_id_hash`     CHAR(64)     NOT NULL COMMENT 'SHA-256 (hex) of the cookie value; the raw id is never stored',
  `tenant_id`           INT          NOT NULL COMMENT '= users.branch_id (home branch)',
  `user_id`             INT          NOT NULL,
  `permission_version`  INT          NOT NULL,
  `department_scope`    JSON         NULL,
  `csrf_token`          VARCHAR(128) NOT NULL COMMENT 'compared with the X-CSRF-Token header on every state-changing request',
  `ip`                  VARCHAR(64)  NULL,
  `user_agent`          VARCHAR(400) NULL,
  `created_at`          DATETIME(3)  NOT NULL,
  `last_seen_at`        DATETIME(3)  NOT NULL,
  `idle_expires_at`     DATETIME(3)  NOT NULL COMMENT 'moves forward with activity (inactivity limit)',
  `absolute_expires_at` DATETIME(3)  NOT NULL COMMENT 'hard limit, never extended',
  `revoked_at`          DATETIME(3)  NULL,
  `revoke_reason`       VARCHAR(30)  NULL COMMENT 'LOGOUT | NEW_LOGIN | PASSWORD_CHANGED | USER_DEACTIVATED | ACCOUNT_LOCKED',
  `scope_mode`          VARCHAR(10)  NULL COMMENT 'NULL = not chosen yet | GLOBAL | BRANCH',
  `scope_branch_id`     INT          NULL,
  PRIMARY KEY (`session_id_hash`),
  KEY `sessions_user_active_idx` (`user_id`, `revoked_at`),
  KEY `sessions_cleanup_idx` (`absolute_expires_at`, `idle_expires_at`),
  CONSTRAINT `sessions_user_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`) ON DELETE CASCADE,
  CONSTRAINT `sessions_scope_chk` CHECK (
    (`scope_mode` IS NULL     AND `scope_branch_id` IS NULL) OR
    (`scope_mode` = 'GLOBAL'  AND `scope_branch_id` IS NULL) OR
    (`scope_mode` = 'BRANCH'  AND `scope_branch_id` IS NOT NULL)
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------- login_history: permanent audit trail (no FK on purpose: history survives deletions)
CREATE TABLE `login_history` (
  `id`         BIGINT       NOT NULL AUTO_INCREMENT,
  `user_id`    INT          NULL COMMENT 'NULL when the username does not exist',
  `username`   VARCHAR(100) NULL,
  `event`      VARCHAR(40)  NOT NULL COMMENT 'LOGIN_SUCCESS | LOGIN_FAILED | LOGIN_BLOCKED | CAPTCHA_FAILED | ACCOUNT_LOCKED | ACCOUNT_UNLOCKED | SESSION_REPLACED | LOGOUT | PASSWORD_CHANGED | SCOPE_SELECTED',
  `reason`     VARCHAR(255) NULL,
  `ip`         VARCHAR(64)  NULL,
  `user_agent` VARCHAR(400) NULL,
  `created_at` DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `login_history_user_idx` (`user_id`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------- captcha_challenges: single use, answer stored hashed
CREATE TABLE `captcha_challenges` (
  `id`          CHAR(36)    NOT NULL COMMENT 'uuid',
  `answer_hash` CHAR(64)    NOT NULL COMMENT 'SHA-256 (hex) of "<id>:<UPPERCASE ANSWER>"',
  `expires_at`  DATETIME(3) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `captcha_expires_idx` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------- reference data
LOCK TABLES `roles` WRITE;
INSERT INTO `roles` (`role_id`, `role_code`, `role_name`, `hierarchy_level`) VALUES
  (1, 'SUPERADMIN', 'Superadmin', 1),
  (2, 'ADMIN',      'Admin',      2),
  (3, 'EMPLOYEE',   'Employee',   3),
  (4, 'OTHER',      'Other',      4);
UNLOCK TABLES;

LOCK TABLES `branches` WRITE;
INSERT INTO `branches` (`branch_id`, `branch_name`, `branch_code`, `sequence`) VALUES (1, 'Head Office', 'HO', 1);
UNLOCK TABLES;

-- No user is created here: a password hash cannot be written by hand. Create the first user with the Node script
-- (npm run user:create) or insert a row into `users` with a scrypt hash made by utils/password.js hashPassword().

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
