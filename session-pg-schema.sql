DROP SCHEMA IF EXISTS session CASCADE;
CREATE SCHEMA session;

CREATE TABLE IF NOT EXISTS session.user (
  sys_user_id char(36) PRIMARY KEY,
  email_addr varchar(256) UNIQUE NOT NULL,
  email_verified boolean NOT NULL,
  verify_token char(36),
  user_id varchar(256) UNIQUE NOT NULL,
  pw_salt varchar(256) NOT NULL,
  pw_crypt varchar(256) NOT NULL,
  first_name varchar(256) NOT NULL,
  last_name varchar(256) NOT NULL,
  created_dt timestamp with time zone NOT NULL,
  login_allowed boolean NOT NULL,
  reset_token varchar(256) UNIQUE, /* encrypted */
  reset_expires timestamp with time zone,
  tz_name varchar(256) NOT NULL
);

CREATE TABLE IF NOT EXISTS session.session (
  session_id varchar(256) PRIMARY KEY,
  sys_user_id char(36) REFERENCES session.user (sys_user_id),
  start_dt timestamp with time zone NOT NULL,
  expires_dt timestamp with time zone NOT NULL,
  ip_addr varchar(256) NOT NULL,
  user_agent varchar(256) NOT NULL
);

CREATE TABLE IF NOT EXISTS session.config (
  SessionTimeout integer,
  SessionMaxLife integer,
  SmtpServerHost varchar(256),
  SmtpServerPort integer,
  SmtpFrom varchar(256),
  SmtpAuthUsername varchar(256),
  SmtpAuthPassword varchar(256),
  SmtpAuthHost varchar(256),
  HttpsHost varchar(256),
  HttpsPort integer,
  HttpsKey text,
  HttpsCert text,
  VerifyTemplate text,
  ResetTemplate text,
  PasswordResetExpiresDuration integer
);

INSERT INTO session.config DEFAULT VALUES;
