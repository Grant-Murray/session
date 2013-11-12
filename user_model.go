package session

import (
	"code.google.com/p/go.crypto/scrypt"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/Grant-Murray/logdb"
	"github.com/lib/pq"
	uuid "github.com/nu7hatch/gouuid"
	"strings"
	"time"
)

type UserDbRow struct {
	sys_user_id    string
	email_addr     string
	email_verified bool
	verify_token   string
	user_id        string
	pw_salt        string
	pw_crypt       string
	first_name     string
	last_name      string
	created_dt     time.Time
	login_allowed  bool
	reset_token    string
	reset_expires  time.Time
	tz_name        string
}

type UserNullables struct {
	verify_token  sql.NullString
	reset_token   sql.NullString
	reset_expires pq.NullTime
}

func (rw *UserDbRow) SetNullables(nullable UserNullables) { /*{{{*/

	// verify_token
	rw.verify_token = ""
	if nullable.verify_token.Valid {
		rw.verify_token = nullable.verify_token.String
	}

	// reset_token
	rw.reset_token = ""
	if nullable.reset_token.Valid {
		rw.reset_token = nullable.reset_token.String
	}

	// reset_expires
	rw.reset_expires = time.Date(1888, time.January, 1, 0, 0, 0, 0, time.UTC)
	if nullable.reset_expires.Valid {
		rw.reset_expires = nullable.reset_expires.Time
	}
} /*}}}*/

// encrypt uses scrypt
// https://code.google.com/p/go/source/browse/?repo=crypto#hg%2Fscrypt
// to derive a secure key
func encrypt(salt string, clearstr string) (crypt string, err error) { /*{{{*/

	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		logdb.Attn.Printf("Undecodable pw_salt (%s)", salt)
		return
	}

	combined := make([]byte, 64+32)
	_ = copy(combined[0:64], Conf.ServerKey)
	_ = copy(combined[64:], saltBytes)

	cryptBytes, err := scrypt.Key([]byte(clearstr), combined, 65536, 8, 1, 64)
	if err != nil {
		logdb.Attn.Printf("Failure in execution of scrypt: %s", err)
	}
	crypt = hex.EncodeToString(cryptBytes)
	return crypt, err
} /*}}}*/

// SelectUser attempts to read a session.user from the database, it interprets UserIdentifier in three different ways, as a SysUserId, EmailAddr or UserId. It returns an error if not found and a db row otherwise.
func SelectUser(UserIdentifier string) (rw *UserDbRow, err error) { /*{{{*/

	rw = new(UserDbRow)
	var nullable UserNullables

	const sqlfmt = `SELECT 
                     sys_user_id, 
                     email_addr, 
                     email_verified, 
                     verify_token, 
                     user_id, 
                     pw_salt, 
                     pw_crypt, 
                     first_name, 
                     last_name, 
                     created_dt, 
                     login_allowed, 
                     reset_token, 
                     reset_expires, 
                     tz_name 
                   FROM session.user 
                   WHERE %s = $1`

	// UserIdentifier is not SysUserId if it does not parse as a uuid
	_, err = uuid.ParseHex(UserIdentifier)
	if err == nil {
		// 1. try by sys_user_id
		err = Conf.DatabaseHandle.QueryRow(fmt.Sprintf(sqlfmt, "sys_user_id"), UserIdentifier).Scan(
			&rw.sys_user_id,
			&rw.email_addr,
			&rw.email_verified,
			&nullable.verify_token,
			&rw.user_id,
			&rw.pw_salt,
			&rw.pw_crypt,
			&rw.first_name,
			&rw.last_name,
			&rw.created_dt,
			&rw.login_allowed,
			&nullable.reset_token,
			&nullable.reset_expires,
			&rw.tz_name)
		if err == nil {
			rw.SetNullables(nullable)
			return rw, err
		} else if err != sql.ErrNoRows {
			logdb.Attn.Printf("SelectUser failed: %s", err)
			return nil, err
		}
	}

	// UserIdentifier is not EmailAddr if it does not contain @
	if strings.Index(UserIdentifier, "@") < 0 {
		// 2. try by user_id
		err = Conf.DatabaseHandle.QueryRow(fmt.Sprintf(sqlfmt, "user_id"), UserIdentifier).Scan(
			&rw.sys_user_id,
			&rw.email_addr,
			&rw.email_verified,
			&nullable.verify_token,
			&rw.user_id,
			&rw.pw_salt,
			&rw.pw_crypt,
			&rw.first_name,
			&rw.last_name,
			&rw.created_dt,
			&rw.login_allowed,
			&nullable.reset_token,
			&nullable.reset_expires,
			&rw.tz_name)
		if err == nil {
			rw.SetNullables(nullable)
			return rw, err
		} else if err != sql.ErrNoRows {
			logdb.Attn.Printf("SelectUser failed: %s", err)
			return nil, err
		}
	}

	// 3. try by email_addr
	err = Conf.DatabaseHandle.QueryRow(fmt.Sprintf(sqlfmt, "email_addr"), UserIdentifier).Scan(
		&rw.sys_user_id,
		&rw.email_addr,
		&rw.email_verified,
		&nullable.verify_token,
		&rw.user_id,
		&rw.pw_salt,
		&rw.pw_crypt,
		&rw.first_name,
		&rw.last_name,
		&rw.created_dt,
		&rw.login_allowed,
		&nullable.reset_token,
		&nullable.reset_expires,
		&rw.tz_name)
	if err == nil {
		rw.SetNullables(nullable)
		return rw, err
	} else if err != sql.ErrNoRows {
		logdb.Attn.Printf("SelectUser failed: %s", err)
		return nil, err
	}
	return
} /*}}}*/

// PasswordMatches checks if the given ClearPassword matches the one encrypted in rw
func (rw *UserDbRow) PasswordMatches(ClearPassword string) bool { /*{{{*/

	supplied, err := encrypt(rw.pw_salt, ClearPassword)
	if err != nil {
		return false
	}

	if supplied == rw.pw_crypt {
		return true
	}
	return false
} /*}}}*/

func (rw *UserDbRow) SetEncryptedPassword(ClearPassword string) (err error) { /*{{{*/
	pwSaltBytes := makeSalt()
	rw.pw_salt = hex.EncodeToString(pwSaltBytes)

	if rw.pw_crypt, err = encrypt(rw.pw_salt, ClearPassword); err != nil {
		logdb.Attn.Printf("Failed to encrypt password: %s", err)
		return err
	}

	return nil
} /*}}}*/

// MakeSystemUserId generates a fresh UUID to use as the system user id and returns it
func (rw *UserDbRow) MakeSystemUserId() (string, error) { /*{{{*/
	u4, err := uuid.NewV4()
	if err != nil {
		logdb.Attn.Printf("Failed to generate a uuid as sys_user_id: %s", err)
		return "", err
	}

	rw.sys_user_id = u4.String()
	return rw.sys_user_id, nil
} /*}}}*/

// MakeVerifyToken generates a fresh UUID to use as the email verification token and returns it
func (rw *UserDbRow) MakeVerifyToken() error { /*{{{*/
	rw.verify_token = ""
	u4, err := uuid.NewV4()
	if err != nil {
		logdb.Attn.Printf("Failed to generate a uuid as verify_token: %s", err)
		return err
	}

	rw.verify_token = u4.String()
	logdb.Debug.Printf("Using %s as verify token for sys_user_id %s", rw.verify_token, rw.sys_user_id)
	return nil
} /*}}}*/

// encryptResetToken uses SysUserId as the salt and returns reset_token the encrypted hex encoded version
func encryptResetToken(clearResetToken string, SysUserId string) (reset_token string, err error) {

	//  salt = SysUserId + SysUserId
	suid := strings.Join(strings.Split(SysUserId, `-`), "")
	salt := suid + suid

	reset_token, err = encrypt(salt, clearResetToken)
	if err != nil {
		logdb.Attn.Printf("Failed to encrypt reset token: %s", err)
		return
	}

	return reset_token, nil
}

// MakeResetToken generates a fresh UUID to use as the password reset token and returns it after storing an encrypted version on the user record
func (rw *UserDbRow) UpdateResetToken() (clearResetToken string, err error) { /*{{{*/

	clearResetToken = ""
	rw.reset_token = ""

	u4, err := uuid.NewV4()
	if err != nil {
		logdb.Attn.Printf("Failed to generate a uuid as reset_token: %s", err)
		return
	}

	clearResetToken = u4.String()

	rw.reset_token, err = encryptResetToken(clearResetToken, rw.sys_user_id)
	if err != nil {
		logdb.Attn.Printf("encryptResetToken failed: %s", err)
		return
	}

	rw.reset_expires = time.Now().Add(time.Duration(Conf.PasswordResetExpiresDuration) * time.Second)

	updsql := `
    UPDATE session.user SET
      reset_token = $1,
      reset_expires = $2
    WHERE sys_user_id = $3`

	_, err = Conf.DatabaseHandle.Query(updsql, rw.reset_token, rw.reset_expires, rw.sys_user_id)
	if err != nil {
		logdb.Attn.Printf("Database error updating reset token: %s", err)
		return "", err
	}

	logdb.Debug.Printf("Using %s as reset token for sys_user_id %s", rw.reset_token[:8], rw.sys_user_id)
	return

} /*}}}*/

// RemoveResetToken updates the user row, effectively removing the token, since the reset token is sent to the email address on record we also verify the user. This covers the user case where a user registers, forgets their password, asks for a reset.
func (rw *UserDbRow) RemoveResetToken() (err error) { /*{{{*/

	const sql = `UPDATE session.user SET
    reset_token = null,
    reset_expires = null,
    email_verified = true 
    WHERE sys_user_id = $1`

	result, err := Conf.DatabaseHandle.Exec(sql, rw.sys_user_id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows <= 0 {
		err = fmt.Errorf("rows=%d, but one row should have been updated", rows)
		return err
	}

	return nil
} /*}}}*/

func (rw *UserDbRow) InsertUser() (err error) { /*{{{*/

	// insert into table
	const insql = `INSERT INTO session.user (
                     sys_user_id, 
                     email_addr, 
                     email_verified, 
                     verify_token, 
                     user_id, 
                     pw_salt, 
                     pw_crypt, 
                     first_name, 
                     last_name, 
                     created_dt, 
                     login_allowed, 
                     reset_token, 
                     reset_expires, 
                     tz_name)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), $10, NULL, NULL, $11)`

	_, err = Conf.DatabaseHandle.Query(insql,
		rw.sys_user_id,
		rw.email_addr,
		rw.email_verified,
		rw.verify_token,
		rw.user_id,
		rw.pw_salt,
		rw.pw_crypt,
		rw.first_name,
		rw.last_name,
		rw.login_allowed,
		rw.tz_name)

	if err != nil {
		logdb.Attn.Printf("Database error inserting user: %s", err)
		return
	}

	return nil
} /*}}}*/

func (rw *UserDbRow) UpdateUser() (err error) { /*{{{*/

	pwClause := ""
	if rw.pw_salt != "" {
		pwClause = fmt.Sprintf(" pw_salt = '%s', pw_crypt = '%s', ", rw.pw_salt, rw.pw_crypt)
	}

	vtClause := ""
	if rw.verify_token != "**KEEP**" {
		vtClause = fmt.Sprintf(" email_verified = %t, verify_token = '%s', ", rw.email_verified, rw.verify_token)
	}

	// insert into table
	updsql := fmt.Sprintf(`
    UPDATE session.user SET
          email_addr = $1, 
          %s 
          user_id = $2, 
          %s
          first_name = $3, 
          last_name = $4, 
          login_allowed = $5, 
          tz_name = $6
       WHERE sys_user_id = $7`, vtClause, pwClause)

	_, err = Conf.DatabaseHandle.Query(updsql,
		rw.email_addr,
		rw.user_id,
		rw.first_name,
		rw.last_name,
		rw.login_allowed,
		rw.tz_name,
		rw.sys_user_id)

	if err != nil {
		logdb.Attn.Printf("Database error updating user: %s", err)
		return
	}

	return nil
} /*}}}*/
