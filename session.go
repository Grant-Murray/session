package session

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/Grant-Murray/logdb"
	"github.com/Grant-Murray/mailbot"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	uuid "github.com/nu7hatch/gouuid"
	"io"
	"math/big"
	mrand "math/rand"
	"net/http"
	"regexp"
	"strings"
	"text/template"
	"time"
)

const (
	StatusOK      = "OK"
	StatusInvalid = "Invalid"

	// context keys
	RequestLogIdKey   = 0
	CredentialsKey    = 1
	CurrentSessionKey = 2

	emailRegex = `[^@]+?@.{2,128}\.[a-z]{2,44}`
)

// All responses are sent with the JSON encoding of an instance of type Result. The possible values for Status are held in constants StatusOK, StatusInvalid, for example:
//
//    ...
//    "ValidationResult": {
//      "Status": "Invalid",
//      "Message": "Athentication failed",
//      "SystemRef": "doLogin-31661",
//      "PropInError": "UserIdentifier",
//      "PropErrorMsg": "Missing data"
//    }
type Result struct {
	Status       string
	Message      string
	SystemRef    string
	PropInError  string // name of the property in error, e.g. EmailAddr
	PropErrorMsg string // error message related to the PropInError
}

/* Type UserRequest is the type used for initially creating a user and for updating an existing user. For example:

   {
     "EmailAddr": "JaneDoe@Example.Org",
     "UserId": "JDoe99",
     "FirstName": "Jane",
     "LastName": "Doe",
     "TzName": "America/Los_Angeles",
     "ClearPassword": "big-secret-2000",
     "ConfirmPassword": "big-secret-2000"
   }
*/
type UserRequest struct {
	SysUserId       string // blank for insert
	EmailAddr       string // stored as trimmed lower case
	UserId          string // stored as trimmed lower case
	FirstName       string
	LastName        string
	TzName          string
	ClearPassword   string
	ConfirmPassword string
}

type UserResponse struct {
	SysUserId        string
	ValidationResult Result
}

// type verifyEmailTemplateParams holds the values used in the template used to construct the body of the email
type verifyEmailTemplateParams struct {
	EmailAddr string
	FirstName string
	LastName  string
	Token     string
}

// sendVerifyEmail sends an email to td.EmailAddr with Token for verifying the email address used during doUser
func sendVerifyEmail(td verifyEmailTemplateParams) (err error) { /*{{{*/
	tplt := template.Must(template.New("verify email").Parse(Conf.VerifyTemplate))
	tout := new(bytes.Buffer)
	err = tplt.Execute(tout, td)
	if err != nil {
		logdb.Attn.Printf("Verify template failed to execute addr=%s fn=%s ln=%s tok=%s: %s",
			td.EmailAddr, td.FirstName, td.LastName, td.Token, err)
		return err
	}

	logdb.Debug.Printf("Processed template:\n%s bytes", tout.Bytes())

	err = mailbot.UpgradeTLSSend(Conf.Smtp, "", []string{td.EmailAddr}, tout.Bytes())
	if err != nil {
		return err
	}

	logdb.Info.Printf("Verify email sent to %s %s <%s>", td.FirstName, td.LastName, td.EmailAddr)

	return nil
} /*}}}*/

// type resetEmailTemplateParams holds the values used in the template used to construct the body of the email
type resetEmailTemplateParams struct {
	EmailAddr string
	FirstName string
	LastName  string
	Token     string
}

// sendResetEmail sends an email to td.EmailAddr with Token for reseting the email address used during doUser
func sendResetEmail(td resetEmailTemplateParams) (err error) { /*{{{*/
	tplt := template.Must(template.New("reset email").Parse(Conf.ResetTemplate))
	tout := new(bytes.Buffer)
	err = tplt.Execute(tout, td)
	if err != nil {
		logdb.Attn.Printf("Reset template failed to execute addr=%s fn=%s ln=%s tok=%s: %s",
			td.EmailAddr, td.FirstName, td.LastName, td.Token, err)
		return err
	}

	logdb.Debug.Printf("Processed template:\n%s bytes", tout.Bytes())

	err = mailbot.UpgradeTLSSend(Conf.Smtp, "", []string{td.EmailAddr}, tout.Bytes())
	if err != nil {
		return err
	}

	logdb.Info.Printf("Reset email sent to %s %s <%s>", td.FirstName, td.LastName, td.EmailAddr)

	return nil
} /*}}}*/

func validUserRequest(uReq *UserRequest, doingInsert bool, givenSysUserId string, vResult *Result) bool { /*{{{*/

	var err error

	uReq.EmailAddr = strings.TrimSpace(uReq.EmailAddr)
	uReq.EmailAddr = strings.ToLower(uReq.EmailAddr)
	uReq.UserId = strings.TrimSpace(uReq.UserId)
	uReq.UserId = strings.ToLower(uReq.UserId)
	uReq.FirstName = strings.TrimSpace(uReq.FirstName)
	uReq.LastName = strings.TrimSpace(uReq.LastName)
	uReq.TzName = strings.TrimSpace(uReq.TzName)

	if !doingInsert {
		_, err = uuid.ParseHex(uReq.SysUserId)
		if err != nil {
			vResult.PropInError = "SysUserId"
			vResult.PropErrorMsg = "Not a valid UUID"
			return false
		}
		_, err = uuid.ParseHex(givenSysUserId)
		if err != nil {
			vResult.PropInError = "SysUserId"
			vResult.PropErrorMsg = "Not a valid UUID in URL"
			return false
		}

		if uReq.SysUserId != givenSysUserId {
			vResult.PropInError = "SysUserId"
			vResult.PropErrorMsg = "Does not match UUID in URL"
			return false
		}
	}

	if uReq.EmailAddr == "" {
		vResult.PropInError = "EmailAddr"
		vResult.PropErrorMsg = "Missing data"
		return false
	}

	if isMatched, _ := regexp.MatchString(emailRegex, uReq.EmailAddr); !isMatched {
		vResult.PropInError = "EmailAddr"
		vResult.PropErrorMsg = "Not a valid email address"
		return false
	}

	if uReq.UserId == "" {
		vResult.PropInError = "UserId"
		vResult.PropErrorMsg = "Missing data"
		return false
	}

	if strings.Index(uReq.UserId, "@") >= 0 && uReq.UserId != uReq.EmailAddr {
		vResult.PropInError = "UserId"
		vResult.PropErrorMsg = "Must match email address if it contains @"
		return false
	}

	if uReq.FirstName == "" {
		vResult.PropInError = "FirstName"
		vResult.PropErrorMsg = "Missing data"
		return false
	}

	if uReq.LastName == "" {
		vResult.PropInError = "LastName"
		vResult.PropErrorMsg = "Missing data"
		return false
	}

	if uReq.TzName == "" {
		vResult.PropInError = "TzName"
		vResult.PropErrorMsg = "Missing data"
		return false
	}

	if doingInsert || uReq.ClearPassword != "" || uReq.ConfirmPassword != "" {
		if uReq.ClearPassword == "" {
			vResult.PropInError = "ClearPassword"
			vResult.PropErrorMsg = "Missing data"
			return false
		}

		if len(uReq.ClearPassword) < 10 {
			vResult.PropInError = "ClearPassword"
			vResult.PropErrorMsg = "Too short, at least 10 chars"
			return false
		}

		if uReq.ConfirmPassword == "" {
			vResult.PropInError = "ConfirmPassword"
			vResult.PropErrorMsg = "Missing data"
			return false
		}

		if uReq.ConfirmPassword != uReq.ClearPassword {
			vResult.PropInError = "ConfirmPassword"
			vResult.PropErrorMsg = "Passwords did not match"
			return false
		}
	}

	// lookup TzName
	const tzLookupSql = `select count(*) as cnt from pg_timezone_names where 
                    left(name,5) != 'posix' and 
                    left(name,3) != 'Etc' and 
                    length(name) > 3 and 
                    left(name,3) != 'US/' and 
                    left(name,3) != 'GMT' and 
                    name = $1`
	var count int
	err = Conf.DatabaseHandle.QueryRow(tzLookupSql, uReq.TzName).Scan(&count)
	switch {
	case err == sql.ErrNoRows:
		{
			vResult.PropInError = "TzName"
			vResult.PropErrorMsg = "System error"
			return false
		}
	case err != nil:
		{
			vResult.PropInError = "TzName"
			vResult.PropErrorMsg = fmt.Sprintf("System error %s", err)
			logdb.Attn.Printf("Error while executing %s\n($1=%s)\nerr=%s", tzLookupSql, uReq.TzName, err)
			return false
		}
	default:
		{
			if count == 0 {
				vResult.PropInError = "TzName"
				vResult.PropErrorMsg = "Invalid time zone name"
				return false
			}
		}
	}

	// verify EmailAddr unique
	lookupSql := "select count(*) as cnt from session.user where email_addr = $1 and sys_user_id != $2"
	err = Conf.DatabaseHandle.QueryRow(lookupSql, uReq.EmailAddr, uReq.SysUserId).Scan(&count)

	switch {
	case err == sql.ErrNoRows:
		{
			vResult.PropInError = "EmailAddr"
			vResult.PropErrorMsg = "System error"
			return false
		}
	case err != nil:
		{
			vResult.PropInError = "EmailAddr"
			vResult.PropErrorMsg = fmt.Sprintf("System error %s", err)
			logdb.Attn.Printf("Error while executing %s\n($1=%s)\nerr=%s", lookupSql, uReq.EmailAddr, err)
			return false
		}
	default:
		{
			if count > 0 {
				vResult.PropInError = "EmailAddr"
				vResult.PropErrorMsg = "Already associated with a user"
				return false
			}
		}
	}

	// verify UserId unique
	lookupSql = "select count(*) as cnt from session.user where user_id = $1 and sys_user_id != $2"
	err = Conf.DatabaseHandle.QueryRow(lookupSql, uReq.UserId, uReq.SysUserId).Scan(&count)

	switch {
	case err == sql.ErrNoRows:
		{
			vResult.PropInError = "UserId"
			vResult.PropErrorMsg = "System error"
			return false
		}
	case err != nil:
		{
			vResult.PropInError = "UserId"
			vResult.PropErrorMsg = fmt.Sprintf("System error %s", err)
			logdb.Attn.Printf("Error while executing %s\n($1=%s)\nerr=%s", lookupSql, uReq.UserId, err)
			return false
		}
	default:
		{
			if count > 0 {
				vResult.PropInError = "UserId"
				vResult.PropErrorMsg = "Not available"
				return false
			}
		}
	}

	return true
} /*}}}*/

func makeSalt() (salt []byte) { /*{{{*/

	salt = make([]byte, 32)
	n, err := io.ReadFull(rand.Reader, salt)
	if n == len(salt) && err == nil {
		// success, using crypto/rand
		return salt
	} else {
		logdb.Attn.Printf("makeSalt failed to use crypto/rand: %s", err)
	}

	// fallback to math/rand
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	for i := 0; i < len(salt); i++ {
		salt[i] = byte(r.Int())
	}
	return salt
} /*}}}*/

func doUser(rw http.ResponseWriter, req *http.Request) { /*{{{*/
	logTag := context.Get(req, RequestLogIdKey)
	localPrefix := fmt.Sprintf("doUser-%s:", logTag)

	// look at the vars
	doingInsert := true
	givenSysUserId := ""
	vars := mux.Vars(req)
	if len(vars) > 0 {
		doingInsert = false
		givenSysUserId = strings.TrimSpace(vars["SysUserId"])
	}

	logdb.Debug.Printf("%s handling begins: %s (%d bytes)", localPrefix, req.URL, req.ContentLength)

	uReq := new(UserRequest)
	uResp := new(UserResponse)
	uResp.ValidationResult.Status = StatusInvalid
	uResp.ValidationResult.SystemRef = localPrefix
	uResp.ValidationResult.Message = "System error processing user" // should always be overwritten

	var err error

	defer func() {
		// encode response to json and write the response
		enc := json.NewEncoder(rw)
		rw.Header().Add("Content-Type", "application/json")
		err = enc.Encode(uResp)
		if err != nil {
			logdb.Attn.Printf("%s Failed to encode response into json", localPrefix)
		}

		logdb.Debug.Printf("%s handling ends with result message: %s", localPrefix, uResp.ValidationResult.Message)
	}()

	// decode json to struct
	dec := json.NewDecoder(req.Body)
	err = dec.Decode(uReq)
	if err != nil {
		logdb.Attn.Printf("%s Failure while decoding json: %s", localPrefix, err)
		uResp.ValidationResult.Message = fmt.Sprintf("Could not decode the request, got error: %s", err)
		return
	}
	logdb.Debug.Printf("%s decoded JSON request", localPrefix)

	if !doingInsert {
		creds := context.Get(req, CredentialsKey).(*LoginResponse)

		if creds.ValidationResult.Status != StatusOK {
			logdb.Debug.Printf("%s attempt to modify user stopped, invalid session", localPrefix)
			uResp.ValidationResult.Message = "Authentication failure, cannot change profile"
			return
		}

		if creds.SysUserId != givenSysUserId {
			// TODO Feature: an administrator would need to be logged in and authorized
			logdb.Debug.Printf("%s attempt to modify user stopped, logged in user is not profile user", localPrefix)
			uResp.ValidationResult.Message = "Authentication failure, cannot change another users profile"
			return
		}
	}

	if !validUserRequest(uReq, doingInsert, givenSysUserId, &uResp.ValidationResult) {
		uResp.ValidationResult.Message = "Data validation failed"
		return
	}

	// prepare the UserRow
	var userRow = new(UserDbRow)
	userRow.email_addr = uReq.EmailAddr
	userRow.user_id = uReq.UserId
	userRow.first_name = uReq.FirstName
	userRow.last_name = uReq.LastName
	userRow.tz_name = uReq.TzName
	userRow.login_allowed = true // TODO feature to set this after registration

	if doingInsert {
		uResp.SysUserId, err = userRow.MakeSystemUserId()
		if err != nil {
			uResp.ValidationResult.PropInError = "SysUserId"
			uResp.ValidationResult.PropErrorMsg = fmt.Sprintf("%s Server failed to generate a user id: %s", localPrefix, err)
			return
		}
	} else {
		uResp.SysUserId = givenSysUserId
		userRow.sys_user_id = givenSysUserId
	}

	// pw_crypt will not be updated if it is blank
	if uReq.ClearPassword != "" {
		err = userRow.SetEncryptedPassword(uReq.ClearPassword)
		if err != nil {
			uResp.ValidationResult.Message = "System error while encrypting password"
			return
		}
	}

	emailChanged := true
	if !doingInsert {
		oldRow, err := SelectUser(givenSysUserId)
		if err != nil {
			uResp.ValidationResult.Message = "No such user to update"
			return
		}

		if oldRow.email_addr == userRow.email_addr {
			emailChanged = false
			logdb.Debug.Printf("%s Email address unchanged %s", localPrefix, userRow.email_addr)
		} else {
			logdb.Debug.Printf("%s Email address changed from %s --> %s", localPrefix, oldRow.email_addr, userRow.email_addr)
		}
	}

	if emailChanged {
		err = userRow.MakeVerifyToken()
		if err != nil {
			uResp.ValidationResult.Message = "System error while generating email verification token"
			return
		}
		userRow.email_verified = false
	} else {
		userRow.verify_token = "**KEEP**"
	}

	x := "User updated"
	if doingInsert {
		x = "New user registered"
		err = userRow.InsertUser()
		if err != nil {
			uResp.ValidationResult.Message = fmt.Sprintf("%s Database error inserting user: %s", localPrefix, err)
			return
		}
	} else {
		err = userRow.UpdateUser()
		if err != nil {
			uResp.ValidationResult.Message = fmt.Sprintf("%s Database error updating user: %s", localPrefix, err)
			return
		}

		// cache entry becomes dirty when profile data is changed
		vDirty[givenSysUserId] = true
	}

	if emailChanged {
		// send email to prompt for verification
		err = sendVerifyEmail(verifyEmailTemplateParams{EmailAddr: uReq.EmailAddr, FirstName: uReq.FirstName, LastName: uReq.LastName, Token: userRow.verify_token})
		if err != nil {
			// change the message but behave like success
			uResp.ValidationResult.Message = x + " successfully, but email for verification failed to send"
			logdb.Attn.Printf("%s Failure attempting to send email: %s", localPrefix, err)
			return
		}
	}

	logdb.Info.Printf("%s %s: id=%s em=%s fn=%s ln=%s sys=%s",
		localPrefix, x, uReq.UserId, uReq.EmailAddr, uReq.FirstName, uReq.LastName, uResp.SysUserId)

	// BUG(glm) Feature?: Send an email to the administrator, when a new user registers. This obviously would only be switched on for cases where the userbase is small.

	uResp.ValidationResult.Status = StatusOK
	uResp.ValidationResult.Message = x + " successfully"
} /*}}}*/

type VerifyResponse struct {
	EmailAddr        string
	Token            string
	ValidationResult Result
}

func verifyEmail(rw http.ResponseWriter, req *http.Request) { /*{{{*/
	localPrefix := fmt.Sprintf("verifyEmail-%s:", context.Get(req, RequestLogIdKey))
	logdb.Debug.Printf("%s handling begins: %s (%d bytes)", localPrefix, req.URL, req.ContentLength)

	vars := mux.Vars(req)
	var response VerifyResponse
	response.EmailAddr = strings.TrimSpace(strings.ToLower(vars["EmailAddr"]))
	response.Token = vars["Token"]
	response.ValidationResult.Message = "Verification failed"
	response.ValidationResult.Status = StatusInvalid
	response.ValidationResult.SystemRef = localPrefix

	var err error

	defer func() {
		// encode response to json and write the response
		enc := json.NewEncoder(rw)
		rw.Header().Add("Content-Type", "application/json")
		err = enc.Encode(response)
		if err != nil {
			logdb.Attn.Printf("%s Failed to encode response into json", localPrefix)
		}

		logdb.Debug.Printf("%s handling ends with result message: %s", localPrefix, response.ValidationResult.Message)
	}()

	// check if email matches the pattern
	if isMatched, _ := regexp.MatchString(emailRegex, response.EmailAddr); !isMatched {
		response.ValidationResult.PropInError = "EmailAddr"
		response.ValidationResult.PropErrorMsg = "Not a valid email address"
		return
	}

	// validate the token by parsing it
	_, err = uuid.ParseHex(response.Token)
	if err != nil {
		response.ValidationResult.PropInError = "Token"
		response.ValidationResult.PropErrorMsg = "Not a valid token"
		return
	}

	// check the database
	const sql = "update session.user set verify_token = null, email_verified = true where email_addr = $1 and verify_token = $2"
	result, err := Conf.DatabaseHandle.Exec(sql, response.EmailAddr, response.Token)
	if err != nil {
		logdb.Debug.Printf("%s Attempt to verify failed: %s", localPrefix, err)
		return
	}

	rows, err := result.RowsAffected()
	if err != nil {
		logdb.Attn.Printf("%s Error while calling RowsAffected: %s", localPrefix, err)
		return
	}

	if rows > 0 {
		logdb.Info.Printf("%s Email verification of %s. (%d rows updated)", localPrefix, response.EmailAddr, rows)
		response.ValidationResult.Message = "Verification successful"
		response.ValidationResult.Status = StatusOK
	}
} /*}}}*/

/* To start a new session (login), one can identify with EmailAddr, UserId or the system assigned SysUserId. As follows:
   {
     "UserIdentifier": "janedoe@example.org",
     "ClearPassword": "big-secret-2000"
   }

   To continue a session that has not expired then a SessionToken and Salt can be sent. As follows:
   {
     "UserIdentifier": "6ba7b814-9dad-11d1-80b4-00c04fd430c8",
     "SessionToken": "4fd77149-561f-48a5-728e-f6be227c0ea4",
     "Salt": "cf84e7b37d3e8ce781f158a38685da512f1954b3e8a7bb5772489cc03c3f93f7"
   }
*/
type LoginRequest struct {
	UserIdentifier string // EmailAddr|SysUserId|UserId
	ClearPassword  string // not in db

	SessionToken string // UUID representing the session
	Salt         string // needed because SessionToken is encrypted on the server
}

/* Type LoginResponse corresponds to the JSON response to a successful LoginRequest

   {
     "SessionToken": "fbf8b99c-ea3f-4f13-7fc8-c3911da17a30",
     "Salt": "aac7bbc9b39056afa13406641271d0b905d9f0bffea07b5733d4e237ee885ca6",
     "SessionTTL": 600,
     "SysUserId": "11f5f940-b2a2-4847-48c1-c00dd2771c49",
     "UserId": "selenium-one",
     "EmailAddr": "georgek@mailbot.net",
     "EmailVerified": true,
     "FirstName": "George",
     "LastName": "Katsiopolous",
     "TzName": "America/Los_Angeles",
     "ValidationResult": {
         "Status": "OK",
         "Message": "Authentication successful",
         "SystemRef": "doLogin-32822:",
         "PropInError": "",
         "PropErrorMsg": ""
     }
   }
*/
type LoginResponse struct {
	SessionToken     string // UUID representing the session (also in a cookie)
	Salt             string // needed because SessionToken is encrypted on the server (also in a cookie)
	SessionTTL       int    // seconds time-to-live
	SysUserId        string // identifier UUID generated by server (also in a cookie)
	UserId           string
	EmailAddr        string
	EmailVerified    bool
	FirstName        string
	LastName         string
	TzName           string
	ValidationResult Result
}

func DefaultLoginResponse(localPrefix string) (resp *LoginResponse) {
	resp = new(LoginResponse)
	resp.ValidationResult = Result{Status: StatusInvalid, Message: "Authentication failed",
		SystemRef: localPrefix, PropInError: "", PropErrorMsg: ""}
	return resp
}

// genericLogin is called as a web service (doLogin) and as a package func (Verify)
func genericLogin(localPrefix, ipAddress, userAgent string, loginReq LoginRequest, loginResp *LoginResponse) { /*{{{*/

	if loginResp == nil {
		loginResp = DefaultLoginResponse(localPrefix)
	}

	// Simple validation and cleaning
	loginReq.UserIdentifier = strings.ToLower(strings.TrimSpace(loginReq.UserIdentifier))

	if loginReq.UserIdentifier == "" {
		loginResp.ValidationResult.PropInError = "UserIdentifier"
		loginResp.ValidationResult.PropErrorMsg = "Missing data"
		logdb.Debug.Printf("%s blank user identifier", localPrefix)
		return
	}

	// there are 2 ways to login with a ClearPassword or a SessionToken+Salt
	var loginUsingPassword = true

	if loginReq.ClearPassword == "" && loginReq.SessionToken == "" {
		loginResp.ValidationResult.PropInError = "ClearPassword"
		loginResp.ValidationResult.PropErrorMsg = "Missing data"
		logdb.Debug.Printf("%s blank password", localPrefix)
		return
	}

	if loginReq.ClearPassword == "" {
		// assert loginReq.SessionToken != ""
		loginUsingPassword = false
	}

	userRow, err := SelectUser(loginReq.UserIdentifier)
	if err != nil {
		logdb.Debug.Printf("%s SelectUser err: %s", localPrefix, err)
		return
	}

	csi := new(ClearSessionId)
	csi.SessionToken = loginReq.SessionToken
	csi.Salt = loginReq.Salt

	if loginUsingPassword {
		// Check if password matches
		if !userRow.PasswordMatches(loginReq.ClearPassword) {
			logdb.Debug.Printf("%s passwords did not match", localPrefix)
			return
		}
	} else {
		// Check if the session is not expired
		sessionRow, err := SelectValidSession(csi)
		if err != nil || sessionRow == nil {
			logdb.Debug.Printf("%s Error during SelectValidSession call: %s", localPrefix, err)
			loginResp.ValidationResult.PropInError = "SessionToken"
			loginResp.ValidationResult.PropErrorMsg = "Invalid data"
			return
		}

		// QUESTION: If a user is roaming on a cellular network, does their IP address change?
		//           If yes, then this check may be incorrect.
		if ipAddress != sessionRow.ip_addr {
			logdb.Debug.Printf("%s IP address changed from %s to %s, cannot use session token to login", localPrefix, sessionRow.ip_addr, ipAddress)
			return
		}

		if userAgent != sessionRow.user_agent {
			logdb.Debug.Printf("%s user agent changed from %s to %s, cannot use session token to login", localPrefix, userAgent, sessionRow.user_agent)
			return
		}
	}

	// Check if login allowed
	if !userRow.login_allowed {
		logdb.Debug.Printf("%s login not permitted", localPrefix)
		loginResp.ValidationResult.Message = "Login is not permitted"
		return
	}

	// Check if email is verified
	if !userRow.email_verified {
		if len(userRow.verify_token) != 36 {
			logdb.Attn.Printf("%s email_verified is false, but verify_token is invalid on user %s", localPrefix, userRow.email_addr)
		}

		logdb.Debug.Printf("%s login not permitted with unverified email address", localPrefix)
		loginResp.ValidationResult.Message = fmt.Sprintf("Login is not permitted with unverified email address. Email was sent to %s", userRow.email_addr)

		// resend email to prompt for verification
		err = sendVerifyEmail(verifyEmailTemplateParams{EmailAddr: userRow.email_addr, FirstName: userRow.first_name, LastName: userRow.last_name, Token: userRow.verify_token})
		if err != nil {
			loginResp.ValidationResult.Message = fmt.Sprintf("Login is not permitted with unverified email address. In addition, the system failed to resend to %s", userRow.email_addr)
			logdb.Attn.Printf("%s Failure attempting to resend email: %s", localPrefix, err)
		}

		return
	}

	// Authenticated,  update the session

	if loginUsingPassword {
		// Create a new session
		var sr = new(SessionDbRow)
		sr.sys_user_id = userRow.sys_user_id
		sr.ip_addr = ipAddress
		sr.user_agent = userAgent
		csi, err = sr.InsertSession()
		if err != nil {
			loginResp.ValidationResult.Message = "System error prevented session token creation"
			return
		}

		loginResp.SessionToken = csi.SessionToken
		loginResp.Salt = csi.Salt

	} else {
		// Update the existing session
		loginResp.Salt = loginReq.Salt
		loginResp.SessionToken = loginReq.SessionToken
		csi.SessionToken = loginReq.SessionToken
		csi.Salt = loginReq.Salt

		err = ContinueSession(csi)
		if err != nil {
			loginResp.ValidationResult.Message = "System error prevented session row update"
			return
		}
	}

	loginResp.SessionTTL = Conf.SessionTimeout
	loginResp.SysUserId = userRow.sys_user_id
	loginResp.EmailAddr = userRow.email_addr
	loginResp.EmailVerified = userRow.email_verified
	loginResp.UserId = userRow.user_id
	loginResp.FirstName = userRow.first_name
	loginResp.LastName = userRow.last_name
	loginResp.TzName = userRow.tz_name
	loginResp.ValidationResult.Message = "Authentication successful"
	loginResp.ValidationResult.Status = StatusOK

	t := "using token"
	if loginUsingPassword {
		t = "using password"
	}
	logdb.Info.Printf("%s Session %s %s for SysUserId %s", localPrefix,
		loginResp.SessionToken[:8], t, loginResp.SysUserId)

} /*}}}*/

type verifyCacheEntry struct {
	response   *LoginResponse
	staleAfter time.Time
}

var vCache map[string]verifyCacheEntry = make(map[string]verifyCacheEntry, 1000)
var vDirty map[string]bool = make(map[string]bool, 1000)

// VerifyIdentity is used by clients to check if the supplied sess is valid thus confirming the identity of userId, the session is only valid if the ipAddress and userAgent is the same as those in the database
func VerifyIdentity(logTag, userId string, sess ClearSessionId, ipAddress, userAgent string) (resp *LoginResponse) { /*{{{*/

	if userId == "" || sess.SessionToken == "" || sess.Salt == "" || ipAddress == "" || userAgent == "" {
		resp = new(LoginResponse)
		resp.ValidationResult = Result{Status: StatusInvalid, Message: "Missing credentials",
			SystemRef: "Verify", PropInError: "", PropErrorMsg: ""}
		return resp
	}

	localPrefix := fmt.Sprintf("Verify-%s: for SessionToken %s", logTag, sess.SessionToken[:8])
	logdb.Debug.Printf("%s handling begins", localPrefix)

	// clear out all stale and dirty(modified) cache entries
	for k, v := range vCache {
		if vDirty[v.response.SysUserId] {
			delete(vDirty, v.response.SysUserId)
			delete(vCache, k)
		} else if v.staleAfter.Before(time.Now()) {
			delete(vCache, k)
		}
	}

	var cacheKey string = sess.SessionToken + sess.Salt

	// check cache
	entry := vCache[cacheKey]

	if entry.response != nil {
		// return the cached response since it is not stale
		logdb.Debug.Printf("%s cache hit", localPrefix)
		return entry.response
	} else {
		logdb.Debug.Printf("%s cache miss", localPrefix)
	}

	req := LoginRequest{UserIdentifier: userId, SessionToken: sess.SessionToken, Salt: sess.Salt}
	resp = new(LoginResponse)
	genericLogin(localPrefix, ipAddress, userAgent, req, resp)

	if resp == nil {
		logdb.Attn.Printf("%s genericLogin returned nil, but it never should", localPrefix)
		resp = new(LoginResponse)
		resp.ValidationResult = Result{Status: StatusInvalid, Message: "System error",
			SystemRef: "Verify", PropInError: "", PropErrorMsg: ""}
		return resp
	}

	if resp.ValidationResult.Status != StatusOK {
		// do not cache the authentication failures
		logdb.Debug.Printf("%s: %s", localPrefix, resp.ValidationResult.Message)
		return resp
	}

	// cache the response but not longer than secondsToLive
	var secondsToLive int = 60
	if resp.SessionTTL < secondsToLive {
		secondsToLive = resp.SessionTTL
	}

	vCache[cacheKey] = verifyCacheEntry{staleAfter: time.Now().Add(time.Duration(secondsToLive) * time.Second),
		response: resp}
	logdb.Debug.Printf("%s: cached response and finished: %s", localPrefix, resp.ValidationResult.Message)

	return resp
} /*}}}*/

func doLogin(rw http.ResponseWriter, req *http.Request) { /*{{{*/
	localPrefix := fmt.Sprintf("doLogin-%s:", context.Get(req, RequestLogIdKey))
	logdb.Debug.Printf("%s handling begins: %s (%d bytes)", localPrefix, req.URL, req.ContentLength)

	loginReq := new(LoginRequest)
	loginResp := DefaultLoginResponse(localPrefix)
	var err error

	defer func() {
		// encode response to json and write the response
		enc := json.NewEncoder(rw)
		rw.Header().Add("Content-Type", "application/json")
		http.SetCookie(rw, &http.Cookie{
			Name:    "SessionToken",
			Secure:  true,
			Path:    "/",
			Value:   loginResp.SessionToken,
			Expires: time.Now().Add(time.Duration(loginResp.SessionTTL) * time.Second)})
		http.SetCookie(rw, &http.Cookie{
			Name:    "Salt",
			Secure:  true,
			Path:    "/",
			Value:   loginResp.Salt,
			Expires: time.Now().Add(time.Duration(loginResp.SessionTTL) * time.Second)})
		http.SetCookie(rw, &http.Cookie{
			Name:    "SysUserId",
			Secure:  true,
			Path:    "/",
			Value:   loginResp.SysUserId,
			Expires: time.Now().Add(time.Duration(loginResp.SessionTTL) * time.Second)})
		err = enc.Encode(loginResp)
		if err != nil {
			logdb.Attn.Printf("%s Failed to encode response into json", localPrefix)
		}
		logdb.Debug.Printf("%s handling ends with result message: %s", localPrefix, loginResp.ValidationResult.Message)
	}()

	// decode json to struct
	dec := json.NewDecoder(req.Body)
	err = dec.Decode(loginReq)
	if err != nil {
		logdb.Attn.Printf("%s Failure while decoding json: %s", localPrefix, err)
		loginResp.ValidationResult.Message = fmt.Sprintf("Could not decode the request, got error: %s", err)
		return
	}

	// according to doc req.RemoteAddr has no defined format. we assume the first part to : is IP addr
	suppliedIP := req.RemoteAddr[:strings.Index(req.RemoteAddr, ":")]

	genericLogin(localPrefix, suppliedIP, req.Header.Get("User-Agent"), *loginReq, loginResp)

} /*}}}*/

/* doReset takes a url of the form "/session/reset/{EmailAddr}" and sends an email to the given EmailAddr the response is the same as in doLogout, a SystemRef is the only datum returned. No indication of success or failure, on purpose. */
func doReset(rw http.ResponseWriter, req *http.Request) { /*{{{*/
	localPrefix := fmt.Sprintf("doReset-%s:", context.Get(req, RequestLogIdKey))
	logdb.Debug.Printf("%s handling begins: %s (%d bytes)", localPrefix, req.URL, req.ContentLength)

	vars := mux.Vars(req)
	inEmailAddr := strings.TrimSpace(strings.ToLower(vars["EmailAddr"]))

	var err error

	defer func() {
		// encode response to json and write the response
		rw.Header().Add("Content-Type", "application/json")
		rw.Write([]byte(fmt.Sprintf("{ \"SystemRef\": \"%s\" }", localPrefix)))
		logdb.Debug.Printf("%s handling ends", localPrefix)
	}()

	// check if email matches the pattern
	if isMatched, _ := regexp.MatchString(emailRegex, inEmailAddr); !isMatched {
		logdb.Debug.Printf("%s Password reset for %s failed, bad email address", localPrefix, inEmailAddr)
		return
	}

	// fetch the user
	userRow, err := SelectUser(inEmailAddr)
	if err != nil {
		logdb.Debug.Printf("%s SelectUser err: %s", localPrefix, err)
		return
	}

	// check if sufficient time has passed
	if len(userRow.reset_token) > 1 && userRow.reset_expires.After(time.Now()) {
		logdb.Debug.Printf("%s Active reset token already exists", localPrefix)
		return
	}

	clearResetToken, err := userRow.UpdateResetToken()
	if err != nil {
		logdb.Debug.Printf("%s UpdateResetToken err: %s", localPrefix, err)
		return
	}

	// send the email
	err = sendResetEmail(resetEmailTemplateParams{EmailAddr: userRow.email_addr, FirstName: userRow.first_name, LastName: userRow.last_name, Token: clearResetToken})
	if err != nil {
		logdb.Attn.Printf("%s Failure attempting to send the reset email: %s", localPrefix, err)
		return
	}

} /*}}}*/

// useResetToken creates a login session and returns the session cookies so that a user can change their password, for valid reset tokens only (also verifies email address)
func useResetToken(rw http.ResponseWriter, req *http.Request) { /*{{{*/
	localPrefix := fmt.Sprintf("useReset-%s:", context.Get(req, RequestLogIdKey))
	logdb.Debug.Printf("%s handling begins: %s (%d bytes)", localPrefix, req.URL, req.ContentLength)

	vars := mux.Vars(req)
	inEmailAddr := strings.TrimSpace(strings.ToLower(vars["EmailAddr"]))
	inResetToken := vars["Token"]

	response := DefaultLoginResponse(localPrefix)
	response.ValidationResult.Message = "Reset failed"

	var err error

	defer func() {
		// encode response to json and write the response
		enc := json.NewEncoder(rw)
		rw.Header().Add("Content-Type", "application/json")
		err = enc.Encode(response)
		if err != nil {
			logdb.Attn.Printf("%s Failed to encode response into json", localPrefix)
		}

		logdb.Debug.Printf("%s handling ends with result message: %s", localPrefix, response.ValidationResult.Message)
	}()

	// check if email matches the pattern
	if isMatched, _ := regexp.MatchString(emailRegex, inEmailAddr); !isMatched {
		response.ValidationResult.PropInError = "EmailAddr"
		response.ValidationResult.PropErrorMsg = "Not a valid email address"
		return
	}

	// validate the token by parsing it
	_, err = uuid.ParseHex(inResetToken)
	if err != nil {
		response.ValidationResult.PropInError = "ResetToken"
		response.ValidationResult.PropErrorMsg = "Not a valid reset token"
		return
	}

	// fetch the user
	userRow, err := SelectUser(inEmailAddr)
	if err != nil {
		logdb.Debug.Printf("%s SelectUser err: %s", localPrefix, err)
		return
	}

	// tokens must match
	cryptToken, err := encryptResetToken(inResetToken, userRow.sys_user_id)
	if err != nil {
		logdb.Debug.Printf("%s encryptResetToken err: %s", localPrefix, err)
		return
	}

	if userRow.reset_token == "" {
		logdb.Debug.Printf("%s No token in database", localPrefix)
		return
	}

	if cryptToken != userRow.reset_token {
		logdb.Debug.Printf("%s Given token does not match the token on record", localPrefix)
		return
	}

	// token must be active not expired
	if userRow.reset_expires.Before(time.Now()) {
		logdb.Debug.Printf("%s Reset token is expired", localPrefix)
		return
	}

	if err = userRow.RemoveResetToken(); err != nil {
		logdb.Debug.Printf("%s RemoveResetToken err: %s", localPrefix, err)
		return
	}

	// TODO return the correct cookies

} /*}}}*/

type LogoutRequest struct {
	SessionToken string // UUID representing the session
	Salt         string // needed because SessionToken is encrypted on the server
}

// doLogout deletes the session record and returns no response
func doLogout(rw http.ResponseWriter, req *http.Request) { /*{{{*/
	localPrefix := fmt.Sprintf("doLogout-%s:", context.Get(req, RequestLogIdKey))
	logdb.Debug.Printf("%s handling begins: %s (%d bytes)", localPrefix, req.URL, req.ContentLength)

	logoutReq := new(LogoutRequest)

	defer func() {
		rw.Header().Add("Content-Type", "application/json")
		rw.Write([]byte(fmt.Sprintf("{ \"SystemRef\": \"%s\" }", localPrefix)))
		logdb.Debug.Printf("%s handling ends", localPrefix)
	}()

	// decode json to struct
	dec := json.NewDecoder(req.Body)
	err := dec.Decode(logoutReq)
	if err != nil {
		logdb.Attn.Printf("%s Failure while decoding json: %s", localPrefix, err)
		return
	}

	csi := new(ClearSessionId)
	csi.SessionToken = logoutReq.SessionToken
	csi.Salt = logoutReq.Salt

	// remove session from cache
	delete(vCache, logoutReq.SessionToken+logoutReq.Salt)

	rows, err := DeleteSession(csi)
	if err != nil {
		logdb.Debug.Printf("%s Invalid logout request received: %s", localPrefix, err)
		return
	}

	if rows > 0 {
		logdb.Info.Printf("%s Logout of SessionToken %s (%d row deleted)", localPrefix, logoutReq.SessionToken[:8], rows)
	} else {
		logdb.Debug.Printf("%s No such session %s to delete", localPrefix, logoutReq.SessionToken[:8])
	}
} /*}}}*/

// getLogin is a like logging in using only the cookie values
func getLogin(rw http.ResponseWriter, req *http.Request) { /*{{{*/
	localPrefix := fmt.Sprintf("getLogin-%s:", context.Get(req, RequestLogIdKey))
	logdb.Debug.Printf("%s handling begins: %s (%d bytes)", localPrefix, req.URL, req.ContentLength)

	loginResp := context.Get(req, CredentialsKey).(*LoginResponse)
	rw.Header().Add("Content-Type", "application/json")

	// encode response to json and write the response
	enc := json.NewEncoder(rw)
	err := enc.Encode(loginResp)
	if err != nil {
		logdb.Attn.Printf("%s Failed to encode response into json", localPrefix)
	}
	logdb.Debug.Printf("%s handling ends with result message: %s", localPrefix, loginResp.ValidationResult.Message)
} /*}}}*/

func checkCredentials(req *http.Request) { /*{{{*/

	logTag := context.Get(req, RequestLogIdKey)
	localPrefix := fmt.Sprintf("checkCredentials-%s:", logTag)

	// cookies
	SysUserIdCookie := ""
	cookie, err := req.Cookie(`SysUserId`)
	if err == nil {
		SysUserIdCookie = cookie.Value
	}

	SessionTokenCookie := ""
	cookie, err = req.Cookie(`SessionToken`)
	if err == nil {
		SessionTokenCookie = cookie.Value
	}

	SaltCookie := ""
	cookie, err = req.Cookie(`Salt`)
	if err == nil {
		SaltCookie = cookie.Value
	}

	// lookup credentials
	c := VerifyIdentity(logTag.(string), SysUserIdCookie,
		ClearSessionId{SessionToken: SessionTokenCookie, Salt: SaltCookie},
		req.RemoteAddr[:strings.Index(req.RemoteAddr, ":")], req.Header.Get("User-Agent"))

	context.Set(req, CredentialsKey, c)
	context.Set(req, CurrentSessionKey, SessionTokenCookie+SaltCookie)

	logdb.Debug.Printf("%s Status:%s Message:%s", localPrefix, c.ValidationResult.Status, c.ValidationResult.Message)

} /*}}}*/

func Handler(rw http.ResponseWriter, req *http.Request) { /*{{{*/

	requestLogId, err := rand.Int(rand.Reader, big.NewInt(999999))
	if err != nil {
		logdb.Attn.Printf("Failed to get a random number. Err:%s", err)
	}

	context.Set(req, RequestLogIdKey, fmt.Sprintf("%06d", requestLogId))
	logdb.Debug.Printf("Session request tagged %06d started with url: %s", requestLogId, req.URL)

	checkCredentials(req)

	router := mux.NewRouter()
	router.HandleFunc("/session/users", doUser).Methods("PUT")
	router.HandleFunc("/session/user/{SysUserId}", doUser).Methods("POST")
	router.HandleFunc("/session/user/{EmailAddr}/token/{Token}", verifyEmail).Methods("GET")
	router.HandleFunc("/session/login", doLogin).Methods("POST")
	router.HandleFunc("/session/login", getLogin).Methods("GET")
	router.HandleFunc("/session/reset/{EmailAddr}/token/{Token}", useResetToken).Methods("GET")
	router.HandleFunc("/session/reset/{EmailAddr}", doReset).Methods("GET")
	router.HandleFunc("/session/logout", doLogout).Methods("POST")

	router.ServeHTTP(rw, req)
} /*}}}*/
