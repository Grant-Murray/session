DROP SCHEMA IF EXISTS session CASCADE;
CREATE SCHEMA session;

CREATE TABLE IF NOT EXISTS session.user (
  SysUserId char(36) PRIMARY KEY,
  EmailAddr varchar(256) UNIQUE NOT NULL,
  EmailVerified boolean NOT NULL,
  verify_token char(36),
  UserId varchar(256) UNIQUE NOT NULL,
  pw_salt varchar(256) NOT NULL,
  pw_crypt varchar(256) NOT NULL,
  FirstName varchar(256) NOT NULL,
  LastName varchar(256) NOT NULL,
  created_dt timestamp with time zone NOT NULL,
  login_allowed boolean NOT NULL,
  reset_token varchar(256) UNIQUE, /* encrypted */
  reset_expires timestamp with time zone,
  TzName varchar(256) NOT NULL
);

CREATE TABLE IF NOT EXISTS session.session (
  SessionId varchar(256) PRIMARY KEY,
  SysUserId char(36) REFERENCES session.user (SysUserId),
  start_dt timestamp with time zone NOT NULL,
  expires_dt timestamp with time zone NOT NULL,
  IpAddr varchar(256) NOT NULL,
  UserAgent varchar(256) NOT NULL
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
