package session

import (
  "crypto/sha512"
  "encoding/hex"
  "fmt"
  "github.com/golang/glog"
  uuid "github.com/nu7hatch/gouuid"
  "time"
)

type SessionDbRow struct {
  SessionId  string
  SysUserId  string
  start_dt   time.Time
  expires_dt time.Time
  IpAddr     string
  UserAgent  string
}

type ClearSessionId struct {
  SessionToken string
  Salt         string
}

func (csi *ClearSessionId) EncryptToken() (SessionId string, err error) {
  // validate the session token by parsing it
  _, err = uuid.ParseHex(csi.SessionToken)
  if err != nil {
    err = fmt.Errorf("SessionToken (%s) is not a UUID", csi.SessionToken)
    return "", err
  }

  if csi.Salt == "" {
    err = fmt.Errorf("Salt is missing")
    return "", err
  }

  if len(csi.Salt) != 64 {
    err = fmt.Errorf("Salt must be 32 bytes but was %d bytes", len(csi.Salt)/2)
    return "", err
  }

  // scrypt is slow and good for passwords
  // sha512 is faster and good for sessions
  saltBytes, err := hex.DecodeString(csi.Salt)
  if err != nil {
    glog.Errorf("Undecodable salt (%s)", csi.Salt)
    return "", err
  }

  combined := make([]byte, 64+32+36)
  _ = copy(combined[0:64], Conf.ServerKey)
  _ = copy(combined[64:96], saltBytes)
  _ = copy(combined[96:], []byte(csi.SessionToken))

  sum512 := sha512.Sum512(combined)

  SessionId = hex.EncodeToString(sum512[:])

  return SessionId, nil
}

func SelectValidSession(csi *ClearSessionId) (sess *SessionDbRow, err error) {

  hsess, err := csi.EncryptToken()
  if err != nil {
    return nil, err
  }

  // delete all invalid sessions
  delSql := fmt.Sprintf(`
      DELETE FROM session.session 
      WHERE expires_dt < now() OR 
            start_dt < now() - interval '%d second'`, Conf.SessionMaxLife)
  _, err = Conf.DatabaseHandle.Exec(delSql)
  if err != nil {
    glog.Errorf("Failed to delete invalid sessions: %s", err)
    err = fmt.Errorf("System error prevented invalid session removal")
    return nil, err
  }

  sess = new(SessionDbRow)
  // look for the session
  err = Conf.DatabaseHandle.QueryRow(`
      SELECT 
        SessionId,
        SysUserId,
        start_dt,
        expires_dt,
        IpAddr,
        UserAgent
      FROM session.session
      WHERE SessionId = $1`, hsess).Scan(
    &sess.SessionId,
    &sess.SysUserId,
    &sess.start_dt,
    &sess.expires_dt,
    &sess.IpAddr,
    &sess.UserAgent)
  if err != nil {
    return nil, err
  }

  return sess, nil
}

func (sr *SessionDbRow) InsertSession() (csi *ClearSessionId, err error) {

  var u4 *uuid.UUID

  u4, err = uuid.NewV4()
  if err != nil {
    return nil, err
  }

  csi = new(ClearSessionId)

  saltBytes := makeSalt()
  csi.Salt = hex.EncodeToString(saltBytes)
  csi.SessionToken = u4.String()

  sessionIdCrypt, err := csi.EncryptToken()
  if err != nil {
    err = fmt.Errorf("Failed to encrypt SessionToken: %s", err)
    return nil, err
  }

  insertSql := fmt.Sprintf(`
    INSERT INTO session.session (
        SessionId,
        SysUserId,
        start_dt,
        expires_dt,
        IpAddr,
        UserAgent)
     VALUES ($1, $2, now(), now() + interval '%d second', $3, $4)`, Conf.SessionTimeout)

  _, err = Conf.DatabaseHandle.Exec(insertSql, sessionIdCrypt, sr.SysUserId,
    sr.IpAddr, sr.UserAgent)

  if err != nil {
    glog.Errorf("Insert of session row failed: %s", err)
    return nil, err
  }

  return csi, nil
}

func ContinueSession(csi *ClearSessionId) (err error) {

  sessionIdCrypt, err := csi.EncryptToken()
  if err != nil {
    err = fmt.Errorf("Failed to encrypt SessionToken: %s", err)
    return err
  }

  updateSql := fmt.Sprintf(`
      UPDATE session.session SET
        expires_dt = now() + interval '%d second'
      WHERE SessionId = $1`, Conf.SessionTimeout)
  _, err = Conf.DatabaseHandle.Exec(updateSql, sessionIdCrypt)

  if err != nil {
    glog.Errorf("Update of session row failed: %s", err)
    return err
  }

  return nil
}

func DeleteSession(csi *ClearSessionId) (rows int64, err error) {

  sessionIdCrypt, err := csi.EncryptToken()
  if err != nil {
    err = fmt.Errorf("Failed to encrypt SessionToken: %s", err)
    return -1, err
  }

  const delsql = "DELETE FROM session.session where SessionId = $1"
  result, err := Conf.DatabaseHandle.Exec(delsql, sessionIdCrypt)
  if err != nil {
    if glog.V(2) {
      glog.Infof("Attempt to delete session row failed: %s", err)
    }
    return -1, err
  }

  rows, err = result.RowsAffected()
  if err != nil {
    glog.Errorf("Error while calling RowsAffected: %s", err)
    return -1, err
  }

  return rows, nil
}
