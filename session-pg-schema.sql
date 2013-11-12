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
  max_log_days integer default 7,
  debug_verbosely boolean default FALSE,
  session_timeout integer,
  session_max_life integer,
  smtp_server_host varchar(256),
  smtp_server_port integer,
  smtp_from varchar(256),
  smtp_auth_username varchar(256),
  smtp_auth_password varchar(256),
  smtp_auth_host varchar(256),
  https_host varchar(256),
  https_port integer,
  https_key text,
  https_cert text,
  verify_template text,
  reset_template text,
  reset_timeout integer
);

INSERT INTO session.config DEFAULT VALUES;

CREATE TABLE IF NOT EXISTS session.log (
  entered timestamp with time zone,
  level VARCHAR(16),
  msg text
);
INSERT INTO session.log VALUES (now(), 'Info', 'table created');


