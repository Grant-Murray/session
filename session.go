package session

import (
  "bytes"
  "crypto/rand"
  "database/sql"
  "encoding/json"
  "fmt"
  "code.grantmurray.com/mailbot"
  "github.com/golang/glog"
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
  emailRegex    = `[^@]+?@.{2,128}\.[a-z]{2,44}`
)

// context keys
const (
  RequestLogIdKey = iota
  CredentialsKey
  CurrentSessionKey
)

// All responses are sent with the JSON encoding of an instance of type Result. The possible values for Status are held in constants StatusOK, StatusInvalid, for example:
type Result struct {
  Status       string
  Message      string
  SystemRef    string
  PropInError  string // name of the property in error, e.g. EmailAddr
  PropErrorMsg string // error message related to the PropInError
}

/* Type UserRequest is the type used for initially creating a user and for updating an existing user. The field SysUserId is blank for insert otherwise it contains the system id assigned when inserted. */
type UserRequest struct {
  SysUserId       string // blank for insert
  EmailAddr       string
  UserId          string
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

// Type verifyEmailTemplateParams holds the values used in the template used to construct the body of the email
type verifyEmailTemplateParams struct {
  EmailAddr string
  FirstName string
  LastName  string
  Token     string
}

// sendVerifyEmail sends an email to td.EmailAddr with Token for verifying the email address used during doUser
func sendVerifyEmail(td verifyEmailTemplateParams) (err error) {
  tplt := template.Must(template.New("verify email").Parse(Conf.VerifyTemplate))
  tout := new(bytes.Buffer)
  err = tplt.Execute(tout, td)
  if err != nil {
    glog.Errorf("Verify template failed to execute addr=%s fn=%s ln=%s tok=%s: %s", td.EmailAddr, td.FirstName, td.LastName, td.Token, err)
    return err
  }

  if glog.V(2) {
    glog.Infof("Processed template:\n%s", tout.Bytes())
  }

  err = mailbot.UpgradeTLSSend(Conf.Smtp, "", []string{td.EmailAddr}, tout.Bytes())
  if err != nil {
    return err
  }

  if glog.V(1) {
    glog.Infof("Verify email sent to %s %s <%s>", td.FirstName, td.LastName, td.EmailAddr)
  }

  return nil
}

// type resetEmailTemplateParams holds the values used in the template used to construct the body of the email
type resetEmailTemplateParams struct {
  EmailAddr string
  FirstName string
  LastName  string
  Token     string
}

// sendResetEmail sends an email to td.EmailAddr with Token for reseting the email address used during doUser
func sendResetEmail(td resetEmailTemplateParams) (err error) {
  tplt := template.Must(template.New("reset email").Parse(Conf.ResetTemplate))
  tout := new(bytes.Buffer)
  err = tplt.Execute(tout, td)
  if err != nil {
    glog.Errorf("Reset template failed to execute addr=%s fn=%s ln=%s tok=%s: %s", td.EmailAddr, td.FirstName, td.LastName, td.Token, err)
    return err
  }

  if glog.V(2) {
    glog.Infof("Processed template:\n%s", tout.Bytes())
  }

  err = mailbot.UpgradeTLSSend(Conf.Smtp, "", []string{td.EmailAddr}, tout.Bytes())
  if err != nil {
    return err
  }

  return nil
}

func validUserRequest(uReq *UserRequest, doingInsert bool, givenSysUserId string, vResult *Result) bool {

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
      glog.Errorf("Error while executing %s\n($1=%s)\nerr=%s", tzLookupSql, uReq.TzName, err)
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
  lookupSql := "select count(*) as cnt from session.user where EmailAddr = $1 and SysUserId != $2"
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
      glog.Errorf("Error while executing %s\n($1=%s)\nerr=%s", lookupSql, uReq.EmailAddr, err)
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
  lookupSql = "select count(*) as cnt from session.user where UserId = $1 and SysUserId != $2"
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
      glog.Errorf("Error while executing %s\n($1=%s)\nerr=%s", lookupSql, uReq.UserId, err)
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
}

func makeSalt() (salt []byte) {

  salt = make([]byte, 32)
  n, err := io.ReadFull(rand.Reader, salt)
  if n == len(salt) && err == nil {
    // success, using crypto/rand
    return salt
  } else {
    glog.Errorf("makeSalt failed to use crypto/rand: %s", err)
  }

  // fallback to math/rand
  r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
  for i := 0; i < len(salt); i++ {
    salt[i] = byte(r.Int())
  }
  return salt
}

func doUser(rw http.ResponseWriter, req *http.Request) {
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

  if glog.V(2) {
    glog.Infof("%s handling begins: %s (%d bytes)", localPrefix, req.URL, req.ContentLength)
  }

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
      glog.Errorf("%s Failed to encode response into json", localPrefix)
    }

    if glog.V(2) {
      glog.Infof("%s handling ends with result message: %s", localPrefix, uResp.ValidationResult.Message)
    }
    glog.Flush()
  }()

  // decode json to struct
  dec := json.NewDecoder(req.Body)
  err = dec.Decode(uReq)
  if err != nil {
    glog.Errorf("%s Failure while decoding json: %s", localPrefix, err)
    uResp.ValidationResult.Message = fmt.Sprintf("Could not decode the request, got error: %s", err)
    return
  }
  if glog.V(2) {
    glog.Infof("%s decoded JSON request", localPrefix)
  }

  if !doingInsert {
    creds := context.Get(req, CredentialsKey).(*LoginResponse)

    if creds.ValidationResult.Status != StatusOK {
      if glog.V(2) {
        glog.Infof("%s attempt to modify user stopped, invalid session", localPrefix)
      }
      uResp.ValidationResult.Message = "Authentication failure, cannot change profile"
      return
    }

    if creds.SysUserId != givenSysUserId {
      // TODO Feature: an administrator would need to be logged in and authorized
      if glog.V(2) {
        glog.Infof("%s attempt to modify user stopped, logged in user is not profile user", localPrefix)
      }
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
  userRow.EmailAddr = uReq.EmailAddr
  userRow.UserId = uReq.UserId
  userRow.FirstName = uReq.FirstName
  userRow.LastName = uReq.LastName
  userRow.TzName = uReq.TzName
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
    userRow.SysUserId = givenSysUserId
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

    if oldRow.EmailAddr == userRow.EmailAddr {
      emailChanged = false
      if glog.V(2) {
        glog.Infof("%s Email address unchanged %s", localPrefix, userRow.EmailAddr)
      }
    } else {
      if glog.V(2) {
        glog.Infof("%s Email address changed from %s --> %s", localPrefix, oldRow.EmailAddr, userRow.EmailAddr)
      }
    }
  }

  if emailChanged {
    err = userRow.MakeVerifyToken()
    if err != nil {
      uResp.ValidationResult.Message = "System error while generating email verification token"
      return
    }
    userRow.EmailVerified = false
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
  }

  if emailChanged {
    // send email to prompt for verification
    err = sendVerifyEmail(verifyEmailTemplateParams{EmailAddr: uReq.EmailAddr, FirstName: uReq.FirstName, LastName: uReq.LastName, Token: userRow.verify_token})
    if err != nil {
      // change the message but behave like success
      uResp.ValidationResult.Message = x + " successfully, but email for verification failed to send"
      glog.Errorf("%s Failure attempting to send email: %s", localPrefix, err)
      return
    }
  }

  if glog.V(1) {
    glog.Infof("%s %s: id=%s em=%s fn=%s ln=%s sys=%s", localPrefix, x, uReq.UserId, uReq.EmailAddr, uReq.FirstName, uReq.LastName, uResp.SysUserId)
  }

  uResp.ValidationResult.Status = StatusOK
  uResp.ValidationResult.Message = x + " successfully"
}

type VerifyResponse struct {
  EmailAddr        string
  Token            string
  ValidationResult Result
}

func verifyEmail(rw http.ResponseWriter, req *http.Request) {
  localPrefix := fmt.Sprintf("verifyEmail-%s:", context.Get(req, RequestLogIdKey))
  if glog.V(2) {
    glog.Infof("%s handling begins: %s (%d bytes)", localPrefix, req.URL, req.ContentLength)
  }

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
      glog.Errorf("%s Failed to encode response into json", localPrefix)
    }

    if glog.V(2) {
      glog.Infof("%s handling ends with result message: %s", localPrefix, response.ValidationResult.Message)
    }
    glog.Flush()
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
  const sql = "update session.user set verify_token = null, EmailVerified = true where EmailAddr = $1 and verify_token = $2"
  result, err := Conf.DatabaseHandle.Exec(sql, response.EmailAddr, response.Token)
  if err != nil {
    if glog.V(2) {
      glog.Infof("%s Attempt to verify failed: %s", localPrefix, err)
    }
    return
  }

  rows, err := result.RowsAffected()
  if err != nil {
    glog.Errorf("%s Error while calling RowsAffected: %s", localPrefix, err)
    return
  }

  if rows > 0 {
    if glog.V(1) {
      glog.Infof("%s Email verification of %s. (%d rows updated)", localPrefix, response.EmailAddr, rows)
    }
    response.ValidationResult.Message = "Verification successful"
    response.ValidationResult.Status = StatusOK
  }
}

type LoginRequest struct {
  UserIdentifier string // EmailAddr|SysUserId|UserId
  ClearPassword  string // not in db

  SessionToken string // UUID representing the session
  Salt         string // needed because SessionToken is encrypted on the server
}

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

func (loginResp *LoginResponse) setUserData(userRow UserDbRow) {
  loginResp.SessionTTL = Conf.SessionTimeout
  loginResp.SysUserId = userRow.SysUserId
  loginResp.EmailAddr = userRow.EmailAddr
  loginResp.EmailVerified = userRow.EmailVerified
  loginResp.UserId = userRow.UserId
  loginResp.FirstName = userRow.FirstName
  loginResp.LastName = userRow.LastName
  loginResp.TzName = userRow.TzName
}

// genericLogin is called as a web service (doLogin) and as a package func (Verify)
// genericLogin checks the database for a valid session
func genericLogin(localPrefix, ipAddress, userAgent string, loginReq LoginRequest, loginResp *LoginResponse) {

  if loginResp == nil {
    loginResp = DefaultLoginResponse(localPrefix)
  }

  // Simple validation and cleaning
  loginReq.UserIdentifier = strings.ToLower(strings.TrimSpace(loginReq.UserIdentifier))

  if loginReq.UserIdentifier == "" {
    loginResp.ValidationResult.PropInError = "UserIdentifier"
    loginResp.ValidationResult.PropErrorMsg = "Missing data"
    if glog.V(2) {
      glog.Infof("%s blank user identifier", localPrefix)
    }
    return
  }

  // there are 2 ways for UserIdentifier to login: 1)ClearPassword or 2)SessionToken+Salt
  var loginUsingPassword = true

  if loginReq.ClearPassword == "" && loginReq.SessionToken == "" {
    loginResp.ValidationResult.PropInError = "ClearPassword"
    loginResp.ValidationResult.PropErrorMsg = "Missing data"
    if glog.V(2) {
      glog.Infof("%s blank password", localPrefix)
    }
    return
  }

  if loginReq.ClearPassword == "" {
    // assert loginReq.SessionToken != ""
    loginUsingPassword = false
  }

  userRow, err := SelectUser(loginReq.UserIdentifier)
  if err != nil {
    if glog.V(2) {
      glog.Infof("%s SelectUser err: %s", localPrefix, err)
    }
    return
  }

  csi := new(ClearSessionId)
  csi.SessionToken = loginReq.SessionToken
  csi.Salt = loginReq.Salt

  if loginUsingPassword {
    // Check if password matches
    if !userRow.PasswordMatches(loginReq.ClearPassword) {
      if glog.V(2) {
        glog.Infof("%s passwords did not match", localPrefix)
      }
      return
    }
  } else {
    // Check if the session is not expired
    sessionRow, err := SelectValidSession(csi)
    if err != nil || sessionRow == nil {
      if glog.V(2) {
        glog.Infof("%s Error during SelectValidSession call: %s", localPrefix, err)
      }
      loginResp.ValidationResult.PropInError = "SessionToken"
      loginResp.ValidationResult.PropErrorMsg = "Invalid data"
      return
    }

    // QUESTION: If a user is roaming on a cellular network, does their IP address change?
    //           If yes, then this check may be incorrect.
    if ipAddress != sessionRow.IpAddr {
      if glog.V(2) {
        glog.Infof("%s IP address changed from %s to %s, cannot use session token to login", localPrefix, sessionRow.IpAddr, ipAddress)
      }
      return
    }

    if userAgent != sessionRow.UserAgent {
      if glog.V(2) {
        glog.Infof("%s user agent changed from %s to %s, cannot use session token to login", localPrefix, userAgent, sessionRow.UserAgent)
      }
      return
    }
  }

  // Check if login allowed
  if !userRow.login_allowed {
    if glog.V(2) {
      glog.Infof("%s login not permitted", localPrefix)
    }
    loginResp.ValidationResult.Message = "Login is not permitted"
    return
  }

  // Check if email is verified
  if !userRow.EmailVerified {
    if len(userRow.verify_token) != 36 {
      glog.Errorf("%s EmailVerified is false, but verify_token is invalid on user %s", localPrefix, userRow.EmailAddr)
    }

    if glog.V(2) {
      glog.Infof("%s login not permitted with unverified email address", localPrefix)
    }
    loginResp.ValidationResult.Message = fmt.Sprintf("Login is not permitted with unverified email address. Email was sent to %s", userRow.EmailAddr)

    // resend email to prompt for verification
    err = sendVerifyEmail(verifyEmailTemplateParams{EmailAddr: userRow.EmailAddr, FirstName: userRow.FirstName, LastName: userRow.LastName, Token: userRow.verify_token})
    if err != nil {
      loginResp.ValidationResult.Message = fmt.Sprintf("Login is not permitted with unverified email address. In addition, the system failed to resend to %s", userRow.EmailAddr)
      glog.Errorf("%s Failure attempting to resend email: %s", localPrefix, err)
    }

    return
  }

  // Authenticated,  update the session

  if loginUsingPassword {
    // Create a new session
    var sr = new(SessionDbRow)
    sr.SysUserId = userRow.SysUserId
    sr.IpAddr = ipAddress
    sr.UserAgent = userAgent
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

  loginResp.setUserData(*userRow)

  loginResp.ValidationResult.Message = "Authentication successful"
  loginResp.ValidationResult.Status = StatusOK

  t := "using token"
  if loginUsingPassword {
    t = "using password"
  }
  if glog.V(1) {
    glog.Infof("%s Session %s %s for SysUserId %s", localPrefix, loginResp.SessionToken[:8], t, loginResp.SysUserId)
  }

}

// VerifyIdentity is used by clients to check if the supplied sess is valid thus confirming the identity of userId, the session is only valid if the ipAddress and userAgent is the same as those in the database
func VerifyIdentity(logTag, userId string, sess ClearSessionId, ipAddress, userAgent string) (resp *LoginResponse) {

  if userId == "" || sess.SessionToken == "" || sess.Salt == "" || ipAddress == "" || userAgent == "" {
    resp = new(LoginResponse)
    resp.ValidationResult = Result{Status: StatusInvalid, Message: "Missing credentials",
      SystemRef: "Verify", PropInError: "", PropErrorMsg: ""}
    return resp
  }

  localPrefix := fmt.Sprintf("Verify-%s: for SessionToken %s", logTag, sess.SessionToken[:8])
  if glog.V(2) {
    glog.Infof("%s handling begins", localPrefix)
  }

  req := LoginRequest{UserIdentifier: userId, SessionToken: sess.SessionToken, Salt: sess.Salt}
  resp = new(LoginResponse)
  genericLogin(localPrefix, ipAddress, userAgent, req, resp)

  if resp == nil {
    glog.Errorf("%s genericLogin returned nil, but it never should", localPrefix)
    resp = new(LoginResponse)
    resp.ValidationResult = Result{Status: StatusInvalid, Message: "System error",
      SystemRef: "Verify", PropInError: "", PropErrorMsg: ""}
    return resp
  }

  if glog.V(2) {
    glog.Infof("%s: %s", localPrefix, resp.ValidationResult.Message)
  }

  return resp
}

func setSessionCookies(rw http.ResponseWriter, loginResp *LoginResponse) {
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
}

func doLogin(rw http.ResponseWriter, req *http.Request) {
  localPrefix := fmt.Sprintf("doLogin-%s:", context.Get(req, RequestLogIdKey))
  if glog.V(2) {
    glog.Infof("%s handling begins: %s (%d bytes)", localPrefix, req.URL, req.ContentLength)
  }

  loginReq := new(LoginRequest)
  loginResp := DefaultLoginResponse(localPrefix)
  var err error

  defer func() {
    // encode response to json and write the response
    setSessionCookies(rw, loginResp)
    enc := json.NewEncoder(rw)
    rw.Header().Add("Content-Type", "application/json")
    err = enc.Encode(loginResp)
    if err != nil {
      glog.Errorf("%s Failed to encode response into json", localPrefix)
    }
    if glog.V(2) {
      glog.Infof("%s handling ends with result message: %s", localPrefix, loginResp.ValidationResult.Message)
    }
    glog.Flush()
  }()

  // decode json to struct
  dec := json.NewDecoder(req.Body)
  err = dec.Decode(loginReq)
  if err != nil {
    glog.Errorf("%s Failure while decoding json: %s", localPrefix, err)
    loginResp.ValidationResult.Message = fmt.Sprintf("Could not decode the request, got error: %s", err)
    return
  }

  // according to doc req.RemoteAddr has no defined format. we assume the first part to : is IP addr
  suppliedIP := req.RemoteAddr[:strings.Index(req.RemoteAddr, ":")]

  genericLogin(localPrefix, suppliedIP, req.Header.Get("User-Agent"), *loginReq, loginResp)

}

/* getResetToken takes a url of the form "/session/reset/{EmailAddr}" and sends an email to the given EmailAddr the response is the same as in doLogout, a SystemRef is the only datum returned. No indication of success or failure, on purpose. */
func getResetToken(rw http.ResponseWriter, req *http.Request) {
  localPrefix := fmt.Sprintf("getResetToken-%s:", context.Get(req, RequestLogIdKey))
  if glog.V(2) {
    glog.Infof("%s handling begins: %s (%d bytes)", localPrefix, req.URL, req.ContentLength)
  }

  vars := mux.Vars(req)
  inEmailAddr := strings.TrimSpace(strings.ToLower(vars["EmailAddr"]))

  var err error

  defer func() {
    // encode response to json and write the response
    rw.Header().Add("Content-Type", "application/json")
    rw.Write([]byte(fmt.Sprintf("{ \"SystemRef\": \"%s\" }", localPrefix)))
    if glog.V(2) {
      glog.Infof("%s handling ends", localPrefix)
    }
    glog.Flush()
  }()

  // check if email matches the pattern
  if isMatched, _ := regexp.MatchString(emailRegex, inEmailAddr); !isMatched {
    if glog.V(2) {
      glog.Infof("%s Password reset for %s failed, bad email address", localPrefix, inEmailAddr)
    }
    return
  }

  // fetch the user
  userRow, err := SelectUser(inEmailAddr)
  if err != nil {
    if glog.V(2) {
      glog.Infof("%s SelectUser err: %s", localPrefix, err)
    }
    return
  }

  // Check if login allowed
  if !userRow.login_allowed {
    if glog.V(2) {
      glog.Infof("%s login_allowed is false", localPrefix)
    }
    return
  }

  // check if sufficient time has passed
  if len(userRow.reset_token) > 1 && userRow.reset_expires.After(time.Now()) {
    if glog.V(2) {
      glog.Infof("%s Active reset token already exists for %s", localPrefix, inEmailAddr)
    }
    return
  }

  clearResetToken, err := userRow.UpdateResetToken()
  if err != nil {
    if glog.V(2) {
      glog.Infof("%s UpdateResetToken err: %s", localPrefix, err)
    }
    return
  }
  if glog.V(2) {
    glog.Infof("%s Created a reset token for email addess %s (SysUserId=%s)", localPrefix, inEmailAddr, userRow.SysUserId)
  }

  // send the email
  err = sendResetEmail(resetEmailTemplateParams{EmailAddr: userRow.EmailAddr, FirstName: userRow.FirstName, LastName: userRow.LastName, Token: clearResetToken})
  if err != nil {
    glog.Errorf("%s Failure attempting to send the reset email: %s", localPrefix, err)
    return
  }
  if glog.V(1) {
    glog.Infof("%s Password reset email sent to %s %s <%s>", localPrefix, userRow.FirstName, userRow.LastName, inEmailAddr)
  }

}

// useResetToken creates a login session and returns the session cookies so that a user can change their password, for valid reset tokens only (also verifies email address)
func useResetToken(rw http.ResponseWriter, req *http.Request) {
  localPrefix := fmt.Sprintf("useReset-%s:", context.Get(req, RequestLogIdKey))
  if glog.V(2) {
    glog.Infof("%s handling begins: %s (%d bytes)", localPrefix, req.URL, req.ContentLength)
  }

  vars := mux.Vars(req)
  inEmailAddr := strings.TrimSpace(strings.ToLower(vars["EmailAddr"]))
  inResetToken := vars["Token"]

  response := DefaultLoginResponse(localPrefix)
  response.ValidationResult.Message = "Reset failed"

  var err error

  defer func() {
    // encode response to json and write the response
    setSessionCookies(rw, response)
    enc := json.NewEncoder(rw)
    rw.Header().Add("Content-Type", "application/json")
    err = enc.Encode(response)
    if err != nil {
      glog.Errorf("%s Failed to encode response into json", localPrefix)
    }

    if glog.V(2) {
      glog.Infof("%s handling ends with result message: %s", localPrefix, response.ValidationResult.Message)
    }
    glog.Flush()
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
    if glog.V(2) {
      glog.Infof("%s SelectUser err: %s", localPrefix, err)
    }
    return
  }

  // token in db must be there (obviously)
  if userRow.reset_token == "" {
    if glog.V(2) {
      glog.Infof("%s No reset token in database", localPrefix)
    }
    return
  }

  // token must be active not expired (if reset_token is not blank then reset_expires should
  //   be a valid timestamp, so no need to check that)
  if userRow.reset_expires.Before(time.Now()) {
    if glog.V(2) {
      glog.Infof("%s Reset token is expired", localPrefix)
    }
    return
  }

  // Check if login allowed
  if !userRow.login_allowed {
    if glog.V(2) {
      glog.Infof("%s login_allowed is false", localPrefix)
    }
    return
  }

  // tokens must match
  cryptToken, err := encryptResetToken(inResetToken, userRow.SysUserId)
  if err != nil {
    if glog.V(2) {
      glog.Infof("%s encryptResetToken err: %s", localPrefix, err)
    }
    return
  }

  if cryptToken != userRow.reset_token {
    if glog.V(2) {
      glog.Infof("%s Given token does not match the token on record", localPrefix)
    }
    return
  }

  if err = userRow.RemoveResetToken(); err != nil {
    if glog.V(2) {
      glog.Infof("%s RemoveResetToken err: %s", localPrefix, err)
    }
    return
  }

  // according to doc req.RemoteAddr has no defined format. we assume the first part to : is IP addr
  suppliedIP := req.RemoteAddr[:strings.Index(req.RemoteAddr, ":")]

  // Create a new session
  var sr = new(SessionDbRow)
  sr.SysUserId = userRow.SysUserId
  sr.IpAddr = suppliedIP
  sr.UserAgent = req.Header.Get("User-Agent")
  csi, err := sr.InsertSession()
  if err != nil {
    response.ValidationResult.Message = "System error prevented session token creation"
    return
  }

  response.SessionToken = csi.SessionToken
  response.Salt = csi.Salt

  response.setUserData(*userRow)

  response.ValidationResult.Message = "Reset request is valid"
  response.ValidationResult.Status = StatusOK

  if glog.V(1) {
    glog.Infof("%s Reset request is valid for email %s (SysUserId %s)", localPrefix, inEmailAddr, response.SysUserId)
  }
}

type LogoutRequest struct {
  SessionToken string // UUID representing the session
  Salt         string // needed because SessionToken is encrypted on the server
}

// doLogout deletes the session record and returns no response
func doLogout(rw http.ResponseWriter, req *http.Request) {
  localPrefix := fmt.Sprintf("doLogout-%s:", context.Get(req, RequestLogIdKey))
  if glog.V(2) {
    glog.Infof("%s handling begins: %s (%d bytes)", localPrefix, req.URL, req.ContentLength)
  }

  logoutReq := new(LogoutRequest)

  defer func() {
    rw.Header().Add("Content-Type", "application/json")
    rw.Write([]byte(fmt.Sprintf("{ \"SystemRef\": \"%s\" }", localPrefix)))
    if glog.V(2) {
      glog.Infof("%s handling ends", localPrefix)
    }
    glog.Flush()
  }()

  // decode json to struct
  dec := json.NewDecoder(req.Body)
  err := dec.Decode(logoutReq)
  if err != nil {
    glog.Errorf("%s Failure while decoding json: %s", localPrefix, err)
    return
  }

  csi := new(ClearSessionId)
  csi.SessionToken = logoutReq.SessionToken
  csi.Salt = logoutReq.Salt

  rows, err := DeleteSession(csi)
  if err != nil {
    if glog.V(2) {
      glog.Infof("%s Invalid logout request received: %s", localPrefix, err)
    }
    return
  }

  if rows > 0 {
    if glog.V(1) {
      glog.Infof("%s Logout of SessionToken %s (%d row deleted)", localPrefix, logoutReq.SessionToken[:8], rows)
    }
  } else {
    if glog.V(2) {
      glog.Infof("%s No such session %s to delete", localPrefix, logoutReq.SessionToken[:8])
    }
  }
}

// getLogin is a like logging in using only the cookie values
func getLogin(rw http.ResponseWriter, req *http.Request) {
  localPrefix := fmt.Sprintf("getLogin-%s:", context.Get(req, RequestLogIdKey))
  if glog.V(2) {
    glog.Infof("%s handling begins: %s (%d bytes)", localPrefix, req.URL, req.ContentLength)
  }

  loginResp := context.Get(req, CredentialsKey).(*LoginResponse)
  rw.Header().Add("Content-Type", "application/json")

  // encode response to json and write the response
  enc := json.NewEncoder(rw)
  err := enc.Encode(loginResp)
  if err != nil {
    glog.Errorf("%s Failed to encode response into json", localPrefix)
  }
  if glog.V(2) {
    glog.Infof("%s handling ends with result message: %s", localPrefix, loginResp.ValidationResult.Message)
  }
}

// checkCredentials looks up the user credentials and associates the login response with the CredentialsKey
func checkCredentials(req *http.Request) {

  logTag := context.Get(req, RequestLogIdKey)
  localPrefix := fmt.Sprintf("checkCredentials-%s:", logTag)

  // cookies
  SysUserIdCookie := ""
  cookie, err := req.Cookie("SysUserId")
  if err == nil {
    SysUserIdCookie = cookie.Value
  }

  SessionTokenCookie := ""
  cookie, err = req.Cookie("SessionToken")
  if err == nil {
    SessionTokenCookie = cookie.Value
  }

  SaltCookie := ""
  cookie, err = req.Cookie("Salt")
  if err == nil {
    SaltCookie = cookie.Value
  }

  // lookup credentials
  c := VerifyIdentity(logTag.(string), SysUserIdCookie,
    ClearSessionId{SessionToken: SessionTokenCookie, Salt: SaltCookie},
    req.RemoteAddr[:strings.Index(req.RemoteAddr, ":")], req.Header.Get("User-Agent"))

  context.Set(req, CredentialsKey, c)
  context.Set(req, CurrentSessionKey, SessionTokenCookie+SaltCookie)

  if glog.V(2) {
    glog.Infof("%s Status:%s Message:%s", localPrefix, c.ValidationResult.Status, c.ValidationResult.Message)
  }

}

func Handler(rw http.ResponseWriter, req *http.Request) {

  requestLogId, err := rand.Int(rand.Reader, big.NewInt(999999))
  if err != nil {
    glog.Errorf("Failed to get a random number. Err:%s", err)
  }

  context.Set(req, RequestLogIdKey, fmt.Sprintf("%06d", requestLogId))
  if glog.V(2) {
    glog.Infof("Session request tagged %06d started with url: %s", requestLogId, req.URL)
  }

  checkCredentials(req)

  router := mux.NewRouter()
  router.HandleFunc("/session/users", doUser).Methods("PUT")
  router.HandleFunc("/session/user/{SysUserId}", doUser).Methods("POST")
  router.HandleFunc("/session/user/{EmailAddr}/token/{Token}", verifyEmail).Methods("GET")
  router.HandleFunc("/session/login", doLogin).Methods("POST")
  router.HandleFunc("/session/login", getLogin).Methods("GET")
  router.HandleFunc("/session/reset/{EmailAddr}", getResetToken).Methods("GET")
  router.HandleFunc("/session/reset/{EmailAddr}/token/{Token}", useResetToken).Methods("GET")
  router.HandleFunc("/session/logout", doLogout).Methods("POST")

  router.ServeHTTP(rw, req)
}
