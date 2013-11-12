package session

import (
	"encoding/hex"
	"fmt"
	"github.com/Grant-Murray/logdb"
	uuid "github.com/nu7hatch/gouuid"
	"time"
)

type SessionDbRow struct {
	session_id  string
	sys_user_id string
	start_dt    time.Time
	expires_dt  time.Time
	ip_addr     string
	user_agent  string
}

type ClearSessionId struct {
	SessionToken string
	Salt         string
}

func (csi *ClearSessionId) EncryptToken() (session_id string, err error) {
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

	session_id, err = encrypt(csi.Salt, csi.SessionToken)
	if err != nil {
		logdb.Attn.Printf("Encryption failed: %s", err)
		err = fmt.Errorf("Encryption failed: %s", err)
		return "", err
	}

	return session_id, nil
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
		logdb.Attn.Printf("Failed to delete invalid sessions: %s", err)
		err = fmt.Errorf("System error prevented invalid session removal")
		return nil, err
	}

	sess = new(SessionDbRow)
	// look for the session
	err = Conf.DatabaseHandle.QueryRow(`
      SELECT 
        session_id,
        sys_user_id,
        start_dt,
        expires_dt,
        ip_addr,
        user_agent
      FROM session.session
      WHERE session_id = $1`, hsess).Scan(
		&sess.session_id,
		&sess.sys_user_id,
		&sess.start_dt,
		&sess.expires_dt,
		&sess.ip_addr,
		&sess.user_agent)
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
        session_id,
        sys_user_id,
        start_dt,
        expires_dt,
        ip_addr,
        user_agent)
     VALUES ($1, $2, now(), now() + interval '%d second', $3, $4)`, Conf.SessionTimeout)

	_, err = Conf.DatabaseHandle.Exec(insertSql, sessionIdCrypt, sr.sys_user_id,
		sr.ip_addr, sr.user_agent)

	if err != nil {
		logdb.Attn.Printf("Insert of session row failed: %s", err)
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
      WHERE session_id = $1`, Conf.SessionTimeout)
	_, err = Conf.DatabaseHandle.Exec(updateSql, sessionIdCrypt)

	if err != nil {
		logdb.Attn.Printf("Update of session row failed: %s", err)
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

	const delsql = "DELETE FROM session.session where session_id = $1"
	result, err := Conf.DatabaseHandle.Exec(delsql, sessionIdCrypt)
	if err != nil {
		logdb.Debug.Printf("Attempt to delete session row failed: %s", err)
		return -1, err
	}

	rows, err = result.RowsAffected()
	if err != nil {
		logdb.Attn.Printf("Error while calling RowsAffected: %s", err)
		return -1, err
	}

	return rows, nil
}
