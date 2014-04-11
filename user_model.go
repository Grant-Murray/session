package session

import (
  "code.google.com/p/go.crypto/scrypt"
  "database/sql"
  "encoding/hex"
  "fmt"
  "github.com/golang/glog"
  "github.com/lib/pq"
  uuid "github.com/nu7hatch/gouuid"
  "strings"
  "time"
)

type UserDbRow struct {
  SysUserId     string
  EmailAddr     string
  EmailVerified bool
  verify_token  string
  UserId        string
  pw_salt       string
  pw_crypt      string
  FirstName     string
  LastName      string
  created_dt    time.Time
  login_allowed bool
  reset_token   string
  reset_expires time.Time
  TzName        string
}

type UserNullables struct {
  verify_token  sql.NullString
  reset_token   sql.NullString
  reset_expires pq.NullTime
}

func (rw *UserDbRow) SetNullables(nullable UserNullables) {

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
}

// encrypt uses scrypt
// https://code.google.com/p/go/source/browse/?repo=crypto#hg%2Fscrypt
// to derive a secure key
func encrypt(salt string, clearstr string) (crypt string, err error) {

  saltBytes, err := hex.DecodeString(salt)
  if err != nil {
    glog.Errorf("Undecodable pw_salt (%s)", salt)
    return
  }

  combined := make([]byte, 64+32)
  _ = copy(combined[0:64], Conf.ServerKey)
  _ = copy(combined[64:], saltBytes)

  cryptBytes, err := scrypt.Key([]byte(clearstr), combined, 65536, 8, 1, 64)
  if err != nil {
    glog.Errorf("Failure in execution of scrypt: %s", err)
  }
  crypt = hex.EncodeToString(cryptBytes)
  return crypt, err
}

// SelectUser attempts to read a session.user from the database, it interprets UserIdentifier in three different ways, as a SysUserId, EmailAddr or UserId. It returns an error if not found and a db row otherwise.
func SelectUser(UserIdentifier string) (rw *UserDbRow, err error) {

  rw = new(UserDbRow)
  var nullable UserNullables

  const sqlfmt = `SELECT 
                     SysUserId, 
                     EmailAddr, 
                     EmailVerified, 
                     verify_token, 
                     UserId, 
                     pw_salt, 
                     pw_crypt, 
                     FirstName, 
                     LastName, 
                     created_dt, 
                     login_allowed, 
                     reset_token, 
                     reset_expires, 
                     TzName 
                   FROM session.user 
                   WHERE %s = $1`

  // UserIdentifier is not SysUserId if it does not parse as a uuid
  _, err = uuid.ParseHex(UserIdentifier)
  if err == nil {
    // 1. try by SysUserId
    err = Conf.DatabaseHandle.QueryRow(fmt.Sprintf(sqlfmt, "SysUserId"), UserIdentifier).Scan(
      &rw.SysUserId,
      &rw.EmailAddr,
      &rw.EmailVerified,
      &nullable.verify_token,
      &rw.UserId,
      &rw.pw_salt,
      &rw.pw_crypt,
      &rw.FirstName,
      &rw.LastName,
      &rw.created_dt,
      &rw.login_allowed,
      &nullable.reset_token,
      &nullable.reset_expires,
      &rw.TzName)
    if err == nil {
      rw.SetNullables(nullable)
      return rw, err
    } else if err != sql.ErrNoRows {
      glog.Errorf("SelectUser failed: %s", err)
      return nil, err
    }
  }

  // UserIdentifier is not EmailAddr if it does not contain @
  if strings.Index(UserIdentifier, "@") < 0 {
    // 2. try by UserId
    err = Conf.DatabaseHandle.QueryRow(fmt.Sprintf(sqlfmt, "UserId"), UserIdentifier).Scan(
      &rw.SysUserId,
      &rw.EmailAddr,
      &rw.EmailVerified,
      &nullable.verify_token,
      &rw.UserId,
      &rw.pw_salt,
      &rw.pw_crypt,
      &rw.FirstName,
      &rw.LastName,
      &rw.created_dt,
      &rw.login_allowed,
      &nullable.reset_token,
      &nullable.reset_expires,
      &rw.TzName)
    if err == nil {
      rw.SetNullables(nullable)
      return rw, err
    } else if err != sql.ErrNoRows {
      glog.Errorf("SelectUser failed: %s", err)
      return nil, err
    }
  }

  // 3. try by EmailAddr
  err = Conf.DatabaseHandle.QueryRow(fmt.Sprintf(sqlfmt, "EmailAddr"), UserIdentifier).Scan(
    &rw.SysUserId,
    &rw.EmailAddr,
    &rw.EmailVerified,
    &nullable.verify_token,
    &rw.UserId,
    &rw.pw_salt,
    &rw.pw_crypt,
    &rw.FirstName,
    &rw.LastName,
    &rw.created_dt,
    &rw.login_allowed,
    &nullable.reset_token,
    &nullable.reset_expires,
    &rw.TzName)
  if err == nil {
    rw.SetNullables(nullable)
    return rw, err
  } else if err != sql.ErrNoRows {
    glog.Errorf("SelectUser failed: %s", err)
    return nil, err
  }
  return
}

// PasswordMatches checks if the given ClearPassword matches the one encrypted in rw
func (rw *UserDbRow) PasswordMatches(ClearPassword string) bool {

  supplied, err := encrypt(rw.pw_salt, ClearPassword)
  if err != nil {
    return false
  }

  if supplied == rw.pw_crypt {
    return true
  }
  return false
}

func (rw *UserDbRow) SetEncryptedPassword(ClearPassword string) (err error) {
  pwSaltBytes := makeSalt()
  rw.pw_salt = hex.EncodeToString(pwSaltBytes)

  if rw.pw_crypt, err = encrypt(rw.pw_salt, ClearPassword); err != nil {
    glog.Errorf("Failed to encrypt password: %s", err)
    return err
  }

  return nil
}

// MakeSystemUserId generates a fresh UUID to use as the system user id and returns it
func (rw *UserDbRow) MakeSystemUserId() (string, error) {
  u4, err := uuid.NewV4()
  if err != nil {
    glog.Errorf("Failed to generate a uuid as SysUserId: %s", err)
    return "", err
  }

  rw.SysUserId = u4.String()
  return rw.SysUserId, nil
}

// MakeVerifyToken generates a fresh UUID to use as the email verification token and returns it
func (rw *UserDbRow) MakeVerifyToken() error {
  rw.verify_token = ""
  u4, err := uuid.NewV4()
  if err != nil {
    glog.Errorf("Failed to generate a uuid as verify_token: %s", err)
    return err
  }

  rw.verify_token = u4.String()
  if glog.V(2) {
    glog.Infof("Using %s as verify token for SysUserId %s", rw.verify_token, rw.SysUserId)
  }
  return nil
}

// encryptResetToken uses SysUserId as the salt and returns reset_token the encrypted hex encoded version
func encryptResetToken(clearResetToken string, SysUserId string) (reset_token string, err error) {

  //  salt = SysUserId + SysUserId
  suid := strings.Join(strings.Split(SysUserId, `-`), "")
  salt := suid + suid

  reset_token, err = encrypt(salt, clearResetToken)
  if err != nil {
    glog.Errorf("Failed to encrypt reset token: %s", err)
    return
  }

  return reset_token, nil
}

// UpdateResetToken generates a fresh UUID to use as the password reset token and returns it after storing an encrypted version on the user record
func (rw *UserDbRow) UpdateResetToken() (clearResetToken string, err error) {

  clearResetToken = ""
  rw.reset_token = ""

  u4, err := uuid.NewV4()
  if err != nil {
    glog.Errorf("Failed to generate a uuid as reset_token: %s", err)
    return
  }

  clearResetToken = u4.String()

  rw.reset_token, err = encryptResetToken(clearResetToken, rw.SysUserId)
  if err != nil {
    glog.Errorf("encryptResetToken failed: %s", err)
    return
  }

  rw.reset_expires = time.Now().Add(time.Duration(Conf.PasswordResetExpiresDuration) * time.Second)

  updsql := `
    UPDATE session.user SET
      reset_token = $1,
      reset_expires = $2
    WHERE SysUserId = $3`

  _, err = Conf.DatabaseHandle.Query(updsql, rw.reset_token, rw.reset_expires, rw.SysUserId)
  if err != nil {
    glog.Errorf("Database error updating reset token: %s", err)
    return "", err
  }

  return

}

// setLoginAllowed sets the value of login_allowed, this is only used in testing
func (rw *UserDbRow) setLoginAllowed(val bool) (err error) {

  updsql := fmt.Sprintf("UPDATE session.user SET login_allowed = %t WHERE SysUserId = $1", val)

  _, err = Conf.DatabaseHandle.Query(updsql, rw.SysUserId)
  if err != nil {
    glog.Errorf("Database error setting login_allowed: %s", err)
    return err
  }

  if glog.V(2) {
    glog.Infof("setLoginAllowed called successfully (set to %t) for SysUserId %s", val, rw.SysUserId)
  }
  return

}

// expireResetToken expires the password reset token, this is only used in testing
func (rw *UserDbRow) expireResetToken() (err error) {

  rw.reset_expires = time.Now().Add(-time.Second)

  updsql := `
    UPDATE session.user SET
      reset_expires = $1
    WHERE SysUserId = $2 and reset_token is not null`

  _, err = Conf.DatabaseHandle.Query(updsql, rw.reset_expires, rw.SysUserId)
  if err != nil {
    glog.Errorf("Database error expiring reset token: %s", err)
    return err
  }

  if glog.V(2) {
    glog.Infof("Expired reset token for SysUserId %s", rw.SysUserId)
  }
  return

}

// RemoveResetToken updates the user row, effectively removing the token, since the reset token is sent to the email address on record we also verify the email address. This covers the use case where a user registers, forgets their password, asks for a reset.
func (rw *UserDbRow) RemoveResetToken() (err error) {

  const sql = `UPDATE session.user SET
    reset_token = NULL,
    reset_expires = NULL,
    EmailVerified = true,
    verify_token = NULL
    WHERE SysUserId = $1`

  result, err := Conf.DatabaseHandle.Exec(sql, rw.SysUserId)
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
}

func (rw *UserDbRow) InsertUser() (err error) {

  // insert into table
  const insql = `INSERT INTO session.user (
                     SysUserId, 
                     EmailAddr, 
                     EmailVerified, 
                     verify_token, 
                     UserId, 
                     pw_salt, 
                     pw_crypt, 
                     FirstName, 
                     LastName, 
                     created_dt, 
                     login_allowed, 
                     reset_token, 
                     reset_expires, 
                     TzName)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), $10, NULL, NULL, $11)`

  _, err = Conf.DatabaseHandle.Query(insql,
    rw.SysUserId,
    rw.EmailAddr,
    rw.EmailVerified,
    rw.verify_token,
    rw.UserId,
    rw.pw_salt,
    rw.pw_crypt,
    rw.FirstName,
    rw.LastName,
    rw.login_allowed,
    rw.TzName)

  if err != nil {
    glog.Errorf("Database error inserting user: %s", err)
    return
  }

  return nil
}

func (rw *UserDbRow) UpdateUser() (err error) {

  pwClause := ""
  if rw.pw_salt != "" {
    pwClause = fmt.Sprintf(" pw_salt = '%s', pw_crypt = '%s', ", rw.pw_salt, rw.pw_crypt)
  }

  vtClause := ""
  if rw.verify_token != "**KEEP**" {
    vtClause = fmt.Sprintf(" EmailVerified = %t, verify_token = '%s', ", rw.EmailVerified, rw.verify_token)
  }

  // insert into table
  updsql := fmt.Sprintf(`
    UPDATE session.user SET
          EmailAddr = $1, 
          %s 
          UserId = $2, 
          %s
          FirstName = $3, 
          LastName = $4, 
          login_allowed = $5, 
          TzName = $6
       WHERE SysUserId = $7`, vtClause, pwClause)

  _, err = Conf.DatabaseHandle.Query(updsql,
    rw.EmailAddr,
    rw.UserId,
    rw.FirstName,
    rw.LastName,
    rw.login_allowed,
    rw.TzName,
    rw.SysUserId)

  if err != nil {
    glog.Errorf("Database error updating user: %s", err)
    return
  }

  return nil
}
