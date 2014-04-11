/* Session testing.

In order to run these tests, a running sessiond is required as well as a configured mail server (cf. mailbot)
This server key used in these tests needs to match the one used in the running sessiond (see TestSetup for where it is set)

*/
package session

import (
  "bufio"
  "crypto/tls"
  "encoding/json"
  "fmt"
  uuid "github.com/nu7hatch/gouuid"
  "io/ioutil"
  "net/http"
  "net/http/cookiejar"
  "net/url"
  "os"
  "regexp"
  "strings"
  "testing"
  "time"
)

var (
  SavedRow           *UserDbRow
  SavedClearPassword string
  SavedSessionToken  string
  SavedSessionSalt   string
  SavedIpAddress     string = "10.10.10.2" // TODO should do a DNS lookup of Conf.HttpsHost for this
  SavedUserAgent     string = "Agent007-Tester"
  SavedCookieJar     http.CookieJar
  SavedCookieMap     map[string]*http.Cookie // built after calling SavedCookieJar.Cookies(url)
)

const (
  LOGFILENAME = "/tmp/sessiond.glog/sessiond.INFO"
)

func initClient() *http.Client {

  tt := new(http.Transport) // tt => testing transport
  tt.TLSClientConfig = new(tls.Config)
  //tt.TLSClientConfig.InsecureSkipVerify = true

  client := new(http.Client)
  client.Transport = tt
  return client
}

func Test_Config(t *testing.T) {
  if Conf.Smtp.Host != "test.mailbot.net" {
    t.Fatalf("FAIL: Smtp.Host had an unexpected value")
  }

  if Conf.Smtp.Port != 26 {
    t.Fatalf("FAIL: Smtp.Port had an unexpected value")
  }

  if Conf.Smtp.User != "no-reply@mailbot.net" {
    t.Fatalf("FAIL: Smtp.User had an unexpected value")
  }

  if Conf.Smtp.Password != "zFbfrrRUNBdxBHaaJCNh8X" {
    t.Fatalf("FAIL: Smtp.Password had an unexpected value")
  }

  if Conf.Smtp.EmailFrom != "no-reply@mailbot.net" {
    t.Fatalf("FAIL: Smtp.EmailFrom had an unexpected value")
  }
}

// doTestUser makes the call to the server. If SysUserId is blank, it is a PUT /session/users
// otherwise it is a POST /session/user/{SysUserId}
func doTestUser(t *testing.T, SysUserId string, body string) (auResp *UserResponse, err error) {
  client := initClient()
  auResp = new(UserResponse)
  addr := fmt.Sprintf("%s:%d", Conf.HttpsHost, Conf.HttpsPort)
  verb := "PUT"
  srvURL := fmt.Sprintf("https://%s/session/users", addr)
  if SysUserId != "" {
    verb = "POST"
    srvURL = fmt.Sprintf("https://%s/session/user/%s", addr, SysUserId)
  }

  c1 := strings.NewReader(body)

  req, err := http.NewRequest(verb, srvURL, c1)
  if err != nil {
    t.Fatalf("Failed to create a request: %s", err)
    return auResp, err
  }

  // cookies
  if SavedRow != nil {
    client.Jar = SavedCookieJar
  }

  req.Header.Set("User-Agent", SavedUserAgent)

  resp, err := client.Do(req)
  if err != nil {
    t.Fatalf("client request failed: %s", err)
    return auResp, err
  }
  defer resp.Body.Close()

  dec := json.NewDecoder(resp.Body)

  err = dec.Decode(auResp)
  if err != nil {
    t.Fatalf("Error while decoding response body: %s", err)
  }

  return auResp, err
}

var bmarkSessions []*LoginResponse

func Benchmark_Add_User(b *testing.B) {

  client := initClient()
  addr := fmt.Sprintf("%s:%d", Conf.HttpsHost, Conf.HttpsPort)
  url := fmt.Sprintf("https://%s/session/users", addr)
  b.N = 50

  for i := 0; i < b.N; i++ {
    c1 := strings.NewReader(fmt.Sprintf(`
        {
          "EmailAddr": "user%d@example.org",
          "UserId": "user%d",
          "FirstName": "First%d",
          "LastName": "Last%d",
          "ClearPassword": "ABCDEFGHIJ-%d",
          "ConfirmPassword": "ABCDEFGHIJ-%d",
          "TzName": "America/New_York"
        }`, i, i, i, i, i, i))

    req, err := http.NewRequest("PUT", url, c1)
    if err != nil {
      b.Fatalf("Failed to create a request: %s", err)
    }

    req.Header.Set("User-Agent", SavedUserAgent)
    resp, err := client.Do(req)
    if err != nil {
      b.Fatalf("client request failed: %s", err)
    }

    resp.Body.Close()
  }

}

// utility test to set EmailVerified=T for the users created above
func Benchmark_email_verification(b *testing.B) {

  _, err := Conf.DatabaseHandle.Exec("update session.user set EmailVerified = true")
  if err != nil {
    b.Fatalf("Failed to updated EmailVerified: %s", err)
  }

}

func Benchmark_Login(b *testing.B) {

  client := initClient()
  addr := fmt.Sprintf("%s:%d", Conf.HttpsHost, Conf.HttpsPort)
  url := fmt.Sprintf("https://%s/session/login", addr)
  b.N = 50
  bmarkSessions = make([]*LoginResponse, b.N)

  for i := 0; i < b.N; i++ {
    c1 := strings.NewReader(fmt.Sprintf(`{"UserIdentifier":"user%d", "ClearPassword":"ABCDEFGHIJ-%d"}`, i, i))

    req, err := http.NewRequest("POST", url, c1)
    req.Header.Set("User-Agent", SavedUserAgent)
    if err != nil {
      b.Fatalf("Failed to create a request: %s", err)
    }

    req.Header.Set("User-Agent", SavedUserAgent)
    resp, err := client.Do(req)
    if err != nil {
      b.Fatalf("client request failed: %s", err)
    }

    r := new(LoginResponse)
    dec := json.NewDecoder(resp.Body)

    err = dec.Decode(r)
    if err != nil {
      b.Fatalf("Error while decoding response body #%d: %s", i, err)
    }

    if r.ValidationResult.Status != StatusOK {
      b.Fatalf("Failed to login: %s", r.ValidationResult.Message)
    }

    bmarkSessions[i] = r

    resp.Body.Close()
  }
}

func Benchmark_VerifyIdentity(b *testing.B) {

  b.N = 50
  for i := 0; i < b.N; i++ {
    r := bmarkSessions[i]

    vResp := VerifyIdentity(fmt.Sprintf("%06d", i), r.SysUserId, ClearSessionId{SessionToken: r.SessionToken, Salt: r.Salt}, SavedIpAddress, SavedUserAgent)
    if vResp.ValidationResult.Status != StatusOK {
      b.Fatalf("Verify #%d failed: %s", i, vResp.ValidationResult.Message)
    }
  }
}

func Benchmark_VerifyIdentity_cached(b *testing.B) {

  b.N = 5000
  for i := 0; i < b.N; i++ {
    r := bmarkSessions[i%50]

    vResp := VerifyIdentity(fmt.Sprintf("%06d", i), r.SysUserId, ClearSessionId{SessionToken: r.SessionToken, Salt: r.Salt}, SavedIpAddress, SavedUserAgent)
    if vResp.ValidationResult.Status != StatusOK {
      b.Fatalf("Verify #%d failed: %s", i, vResp.ValidationResult.Message)
    }
  }
}

func checkLoggedErrors(SystemRef string, t *testing.T) {
  // look for absence err log messages

  logf, err := os.Open(LOGFILENAME)
  if err != nil {
    t.Fatalf("Log file %s could not be opened: %s", LOGFILENAME, err)
  }
  defer logf.Close()

  scanner := bufio.NewScanner(logf)
  for scanner.Scan() {
    line := scanner.Text()
    if strings.Contains(line, SystemRef) {
      if strings.Index(line, "E") == 0 {
        t.Fatalf("Error found in logfile: %s", line)
        break
      }
    }
  }
  if err := scanner.Err(); err != nil {
    t.Fatalf("Error while reading logfile: %s", err)
  }
}

func checkValidationResult(t *testing.T, auResp *UserResponse) {

  if auResp.ValidationResult.Status != StatusOK {
    t.Errorf("Failed to validate, status:%s", auResp.ValidationResult.Status)
  }

  if !strings.Contains(auResp.ValidationResult.Message, " successfully") {
    t.Errorf("Bad validation result message: %s", auResp.ValidationResult.Message)
  }

  if auResp.ValidationResult.PropInError != "" {
    t.Errorf("Unexpected PropInError: %s", auResp.ValidationResult.PropInError)
  }

  if auResp.ValidationResult.PropErrorMsg != "" {
    t.Errorf("Unexpected PropErrorMsg: %s", auResp.ValidationResult.PropErrorMsg)
  }
}

func checkBadValidationResult(t *testing.T, prop, propM string, auResp *UserResponse) {

  if auResp.ValidationResult.Status != StatusInvalid {
    t.Errorf("Expected invalid status got:%s", auResp.ValidationResult.Status)
  }

  if !strings.Contains(auResp.ValidationResult.Message, "Data validation failed") {
    t.Errorf("Bad validation result message: %s", auResp.ValidationResult.Message)
  }

  if auResp.ValidationResult.PropInError != prop {
    t.Errorf("Unexpected PropInError: %s", auResp.ValidationResult.PropInError)
  }

  if auResp.ValidationResult.PropErrorMsg != propM {
    t.Errorf("Unexpected PropErrorMsg: %s", auResp.ValidationResult.PropErrorMsg)
  }
}

func compareStringColumn(t *testing.T, colName string, actual string, expected string) {

  if expected == "**UUID**" {
    if isMatched, _ := regexp.MatchString(
      "[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}", actual); !isMatched {
      t.Fatalf("%s=%s does not have the pattern of a uuid.", colName, actual)
    }
    return
  }

  if actual != expected {
    t.Errorf("%s: expected \"%s\", got \"%s\"", colName, expected, actual)
  }
}

func compareBoolColumn(t *testing.T, colName string, actual bool, expected bool) {

  if actual != expected {
    t.Errorf("%s: expected \"%t\", got \"%t\"", colName, expected, actual)
  }
}

func verifyEmailTest(em string, tok string, t *testing.T) (vr *VerifyResponse, err error) {
  client := initClient()

  addr := fmt.Sprintf("%s:%d", Conf.HttpsHost, Conf.HttpsPort)
  req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/session/user/%s/token/%s", addr, em, tok), nil)
  if err != nil {
    t.Fatalf("Failed to create a request: %s", err)
    return vr, err
  }

  req.Header.Set("User-Agent", SavedUserAgent)
  resp, err := client.Do(req)
  if err != nil {
    t.Fatalf("client request failed: %s", err)
    return vr, err
  }

  dec := json.NewDecoder(resp.Body)
  vr = new(VerifyResponse)
  err = dec.Decode(vr)
  if err != nil {
    t.Fatalf("Error while decoding response body: %s", err)
  }

  return vr, err
}

func resetEmailTest(em, tok string, t *testing.T) (lr *LoginResponse, err error) {
  client := initClient()
  client.Jar = SavedCookieJar

  addr := fmt.Sprintf("%s:%d", Conf.HttpsHost, Conf.HttpsPort)
  urlStr := fmt.Sprintf("https://%s/session/reset/%s/token/%s", addr, em, tok)

  req, err := http.NewRequest("GET", urlStr, nil)
  if err != nil {
    t.Fatalf("Failed to create a request: %s", err)
    return lr, err
  }

  req.Header.Set("User-Agent", SavedUserAgent)
  resp, err := client.Do(req)
  if err != nil {
    t.Fatalf("client request failed: %s", err)
    return lr, err
  }
  defer resp.Body.Close()

  // load SavedCookieMap
  u, err := url.Parse(fmt.Sprintf("https://%s/", addr))
  if err != nil {
    t.Fatalf("Could not parse url: %s", err)
  }

  cookies := SavedCookieJar.Cookies(u)
  SavedCookieMap = make(map[string]*http.Cookie)
  for _, c := range cookies {
    SavedCookieMap[c.Name] = c
  }

  dec := json.NewDecoder(resp.Body)
  lr = new(LoginResponse)
  err = dec.Decode(lr)
  if err != nil {
    t.Fatalf("Error while decoding response body: %s", err)
  }

  return lr, err
}

type userCase struct {
  descr          string
  suid           string
  jsonStr        string
  UserIdentifier string
  loginUser      string
  loginPassword  string
  expector       func(auResp *UserResponse, ur *UserDbRow, t *testing.T)
}

func userCaseFactory(index int) *userCase {

  switch index {
  case 0:
    return &userCase{
      descr: "create jdoe99 - spaces and caps",
      suid:  "",
      jsonStr: `
        {
          "EmailAddr": "\tGMurray1966@GMail.COM",
          "UserId": "   \tJDoe99  ",
          "FirstName": "  Jane",
          "LastName": "Doe   ",
          "TzName": "   America/Los_Angeles  \t",
          "ClearPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ",
          "ConfirmPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  "
        }`,
      UserIdentifier: "jdoe99",
      loginUser:      "",
      loginPassword:  "",
      expector: func(auResp *UserResponse, ur *UserDbRow, t *testing.T) {
        checkLoggedErrors(auResp.ValidationResult.SystemRef, t)
        checkValidationResult(t, auResp)

        compareStringColumn(t, "SysUserId", ur.SysUserId, "**UUID**")
        compareStringColumn(t, "EmailAddr", ur.EmailAddr, "gmurray1966@gmail.com") /* made lower */
        compareStringColumn(t, "verify_token", ur.verify_token, "**UUID**")
        compareStringColumn(t, "UserId", ur.UserId, "jdoe99")     /* trailing spaces stripped */
        compareStringColumn(t, "FirstName", ur.FirstName, "Jane") /* leading spaces stripped, unchanged case */
        compareStringColumn(t, "LastName", ur.LastName, "Doe")
        compareStringColumn(t, "reset_token", ur.reset_token, "")
        //compareStringColumn(t, "reset_expires", ur.reset_expires, exp.reset_expires)
        compareStringColumn(t, "TzName", ur.TzName, "America/Los_Angeles") /* TrimSpace */

        compareBoolColumn(t, "login_allowed", ur.login_allowed, true)
        compareBoolColumn(t, "EmailVerified", ur.EmailVerified, false)

      }}
  case 1:
    return &userCase{
      descr: "update jdoe99 keep same email address",
      suid:  SavedRow.SysUserId,
      jsonStr: fmt.Sprintf(`
        {
          "SysUserId": "%s",
          "EmailAddr": "\tGMurray1966@GMail.COM",
          "UserId": "   \tJDoe99  ",
          "FirstName": "  Jane",
          "LastName": "  Smith",
          "TzName": "   America/Los_Angeles  \t",
          "ClearPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ",
          "ConfirmPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  "
        }`, SavedRow.SysUserId),
      UserIdentifier: "jdoe99",
      loginUser:      "JDoe99",
      loginPassword:  `  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  `,
      expector: func(auResp *UserResponse, ur *UserDbRow, t *testing.T) {
        checkLoggedErrors(auResp.ValidationResult.SystemRef, t)
        checkValidationResult(t, auResp)

        compareStringColumn(t, "SysUserId", ur.SysUserId, SavedRow.SysUserId)
        compareStringColumn(t, "EmailAddr", ur.EmailAddr, "gmurray1966@gmail.com") // made lower
        compareStringColumn(t, "verify_token", ur.verify_token, "")                // because it is verified
        compareStringColumn(t, "UserId", ur.UserId, "jdoe99")                      // trailing spaces stripped
        compareStringColumn(t, "FirstName", ur.FirstName, "Jane")                  // leading spaces stripped, unchanged case
        compareStringColumn(t, "LastName", ur.LastName, "Smith")
        compareStringColumn(t, "reset_token", ur.reset_token, "")
        //compareStringColumn(t, "reset_expires", ur.reset_expires, exp.reset_expires)
        compareStringColumn(t, "TzName", ur.TzName, "America/Los_Angeles") // TrimSpace

        compareBoolColumn(t, "login_allowed", ur.login_allowed, true)
        compareBoolColumn(t, "EmailVerified", ur.EmailVerified, true) // because it was verified in case 0

      }}
  case 2:
    return &userCase{
      descr: "update jdoe99 new email address no password",
      suid:  SavedRow.SysUserId,
      jsonStr: fmt.Sprintf(`
        {
          "SysUserId": "%s",
          "EmailAddr": "SMITHJ@mailbot.NET",
          "UserId": "   \tJDoe99  ",
          "FirstName": "  Jane",
          "LastName": "  Smith",
          "TzName": "   America/New_York  \t"
        }`, SavedRow.SysUserId),
      UserIdentifier: "jdoe99",
      loginUser:      "JDoe99",
      loginPassword:  `  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  `,
      expector: func(auResp *UserResponse, ur *UserDbRow, t *testing.T) {
        checkLoggedErrors(auResp.ValidationResult.SystemRef, t)
        checkValidationResult(t, auResp)

        compareStringColumn(t, "SysUserId", ur.SysUserId, SavedRow.SysUserId)
        compareStringColumn(t, "EmailAddr", ur.EmailAddr, "smithj@mailbot.net") /* made lower */
        compareStringColumn(t, "verify_token", ur.verify_token, "**UUID**")
        if ur.verify_token == SavedRow.SysUserId {
          t.Errorf("Expected a different verify token because the email address changed")
        }
        compareStringColumn(t, "UserId", ur.UserId, "jdoe99")     /* trailing spaces stripped */
        compareStringColumn(t, "FirstName", ur.FirstName, "Jane") /* leading spaces stripped, unchanged case */
        compareStringColumn(t, "LastName", ur.LastName, "Smith")
        compareStringColumn(t, "reset_token", ur.reset_token, "")
        //compareStringColumn(t, "reset_expires", ur.reset_expires, exp.reset_expires)
        compareStringColumn(t, "TzName", ur.TzName, "America/New_York") /* TrimSpace */

        compareBoolColumn(t, "login_allowed", ur.login_allowed, true)
        compareBoolColumn(t, "EmailVerified", ur.EmailVerified, false)

      }}
  case 3:
    return &userCase{
      descr: "update jdoe99 revert email address, change user id,  no password",
      suid:  SavedRow.SysUserId,
      jsonStr: fmt.Sprintf(`
        {
          "SysUserId": "%s",
          "EmailAddr": "gmurray1966@GMAIL.com",
          "UserId": "SmithyRules!   \t  ",
          "FirstName": "  Big Bob ",
          "LastName": "  Smith",
          "TzName": "   America/New_York  \t"
        }`, SavedRow.SysUserId),
      UserIdentifier: "smithyrules!",
      loginUser:      "JDoe99",
      loginPassword:  `  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  `,
      expector: func(auResp *UserResponse, ur *UserDbRow, t *testing.T) {
        checkLoggedErrors(auResp.ValidationResult.SystemRef, t)
        checkValidationResult(t, auResp)

        compareStringColumn(t, "SysUserId", ur.SysUserId, SavedRow.SysUserId)
        compareStringColumn(t, "EmailAddr", ur.EmailAddr, "gmurray1966@gmail.com") /* made lower */
        compareStringColumn(t, "verify_token", ur.verify_token, "**UUID**")
        if ur.verify_token == SavedRow.SysUserId {
          t.Errorf("Expected a different verify token because the email address changed again")
        }
        compareStringColumn(t, "UserId", ur.UserId, "smithyrules!")  /* trailing spaces stripped */
        compareStringColumn(t, "FirstName", ur.FirstName, "Big Bob") /* leading spaces stripped, unchanged case */
        compareStringColumn(t, "LastName", ur.LastName, "Smith")
        compareStringColumn(t, "reset_token", ur.reset_token, "")
        //compareStringColumn(t, "reset_expires", ur.reset_expires, exp.reset_expires)
        compareStringColumn(t, "TzName", ur.TzName, "America/New_York") /* TrimSpace */

        compareBoolColumn(t, "login_allowed", ur.login_allowed, true)
        compareBoolColumn(t, "EmailVerified", ur.EmailVerified, false)

      }}
  case 4:
    SavedClearPassword = "Simple Secret99"
    return &userCase{
      descr: "update jdoe99 change password",
      suid:  SavedRow.SysUserId,
      jsonStr: fmt.Sprintf(`
        {
          "SysUserId": "%s",
          "EmailAddr": "gmurray1966@GMAIL.com",
          "UserId": "SmithyRules!   \t  ",
          "FirstName": "  Big Bob ",
          "LastName": "  Smith",
          "ClearPassword": "%s",
          "ConfirmPassword": "%s",
          "TzName": "   America/New_York  \t"
        }`, SavedRow.SysUserId, SavedClearPassword, SavedClearPassword),
      UserIdentifier: "smithyrules!",
      loginUser:      "smithyrules!",
      loginPassword:  `  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  `,
      expector: func(auResp *UserResponse, ur *UserDbRow, t *testing.T) {
        checkLoggedErrors(auResp.ValidationResult.SystemRef, t)
        checkValidationResult(t, auResp)

        compareStringColumn(t, "SysUserId", ur.SysUserId, SavedRow.SysUserId)
        compareStringColumn(t, "EmailAddr", ur.EmailAddr, "gmurray1966@gmail.com") /* made lower */
        compareStringColumn(t, "verify_token", ur.verify_token, "")
        if ur.verify_token == SavedRow.SysUserId {
          t.Errorf("Expected a different verify token because the email address changed again")
        }
        compareStringColumn(t, "UserId", ur.UserId, "smithyrules!")  /* trailing spaces stripped */
        compareStringColumn(t, "FirstName", ur.FirstName, "Big Bob") /* leading spaces stripped, unchanged case */
        compareStringColumn(t, "LastName", ur.LastName, "Smith")
        compareStringColumn(t, "reset_token", ur.reset_token, "")
        //compareStringColumn(t, "reset_expires", ur.reset_expires, exp.reset_expires)
        compareStringColumn(t, "TzName", ur.TzName, "America/New_York") /* TrimSpace */

        compareBoolColumn(t, "login_allowed", ur.login_allowed, true)
        compareBoolColumn(t, "EmailVerified", ur.EmailVerified, true)

      }}
  case 5:
    return &userCase{
      descr: "update attempt with bad SysUserId",
      suid:  SavedRow.SysUserId,
      jsonStr: `
        {
          "SysUserId": "6ba7b814-9dad-11d1-80b4-00c04fd430c8",
          "EmailAddr": "gmurray1966@GMAIL.com",
          "UserId": "SmithyRules!   \t  ",
          "FirstName": "  Big Bob ",
          "LastName": "  Smith",
          "TzName": "   America/New_York  \t"
        }`,
      UserIdentifier: "smithyrules!",
      loginUser:      "smithyrules!",
      loginPassword:  "Simple Secret99",
      expector: func(auResp *UserResponse, ur *UserDbRow, t *testing.T) {
        checkLoggedErrors(auResp.ValidationResult.SystemRef, t)
        checkBadValidationResult(t, "SysUserId", "Does not match UUID in URL", auResp)

        compareStringColumn(t, "SysUserId", ur.SysUserId, SavedRow.SysUserId)
        compareStringColumn(t, "EmailAddr", ur.EmailAddr, "gmurray1966@gmail.com") /* made lower */
        compareStringColumn(t, "verify_token", ur.verify_token, "")
        if ur.verify_token == SavedRow.SysUserId {
          t.Errorf("Expected a different verify token because the email address changed again")
        }
        compareStringColumn(t, "UserId", ur.UserId, "smithyrules!")  /* trailing spaces stripped */
        compareStringColumn(t, "FirstName", ur.FirstName, "Big Bob") /* leading spaces stripped, unchanged case */
        compareStringColumn(t, "LastName", ur.LastName, "Smith")
        compareStringColumn(t, "reset_token", ur.reset_token, "")
        //compareStringColumn(t, "reset_expires", ur.reset_expires, exp.reset_expires)
        compareStringColumn(t, "TzName", ur.TzName, "America/New_York") /* TrimSpace */

        compareBoolColumn(t, "login_allowed", ur.login_allowed, true)
        compareBoolColumn(t, "EmailVerified", ur.EmailVerified, true)

      }}
  default:
    return nil
  }
  return nil
}

func getEmail(eAddr string) (bod string, err error) {

  mailbox := eAddr[:strings.Index(eAddr, "@")]
  var mailFile = "/tmp/mailbot.boxes/" + mailbox

  for i := 0; i < 10; i++ {
    var emailB []byte
    emailB, err = ioutil.ReadFile(mailFile)
    if err != nil {
      // especially the very first run, the email takes a short while to arrive

      time.Sleep(500 * time.Millisecond)
      continue
    }
    err = os.Remove(mailFile)
    if err != nil {
      break
    }

    return string(emailB), nil
  }

  return "", err
}

func compareEmailValues(expectEmailAddr string, expectToken string, t *testing.T) {

  email, err := getEmail(expectEmailAddr)
  if err != nil {
    // verification email was not delivered
    t.Fatalf("Unable to read the email: %s", err)
  }

  // parse out the link to get email address and token
  s1 := email[strings.Index(email, "verify/")+7:] // s1 starts at email address
  EmailAddr := s1[:strings.Index(s1, "/")]
  s2 := email[strings.Index(email, "token/")+6:] // s2 starts at the token value
  Token := s2[:strings.Index(s2, "\n")]

  if expectEmailAddr != EmailAddr {
    t.Errorf("EmailAddr was %s, expected it to be %s", EmailAddr, expectEmailAddr)
  }

  // validate the token is UUID by parsing it
  _, err = uuid.ParseHex(Token)
  if err != nil {
    t.Fatalf("Token in email was (%s) but that is not a valid uuid", Token)
  }

  if expectToken != Token {
    t.Errorf("Token was %s, expected it to be %s", Token, expectToken)
  }

  vr, err := verifyEmailTest(expectEmailAddr, expectToken, t)
  if err != nil {
    t.Fatalf("Unexpected error while verifying: %s", err)
  }

  if vr.ValidationResult.Status != StatusOK {
    t.Errorf("Expected OK status after verification but got=%s", vr.ValidationResult.Status)
  }
}

func Test_AddUser(t *testing.T) {

  for i := 0; ; i++ {
    c := userCaseFactory(i)
    if c == nil {
      break
    }

    t.Logf("Case %d: %s", i, c.descr)

    if c.loginUser != "" {
      t.Logf("  - logging in: %s/%s", c.loginUser, c.loginPassword)
      // doing an update so login first
      lcase := &loginCase{"Login for cookies",
        fmt.Sprintf(`{"UserIdentifier":"%s", "ClearPassword":"%s"}`, c.loginUser, c.loginPassword),
        Result{StatusOK, "Authentication successful", "", "", ""}, true,
        "handling ends with result message: Authentication successful"}
      doLoginCase(lcase, t)
    }

    auResp, err := doTestUser(t, c.suid, c.jsonStr)
    if err != nil {
      t.FailNow()
    }

    ur, err := SelectUser(c.UserIdentifier)
    if err != nil {
      t.Fatalf("SelectUser returned with error: %s", err)
    }

    c.expector(auResp, ur, t)

    if !ur.EmailVerified {
      // process validation email like a user would
      compareEmailValues(ur.EmailAddr, ur.verify_token, t)

      afterUr, err := SelectUser(c.UserIdentifier)
      if err != nil {
        t.Fatalf("SelectUser returned with error: %s", err)
      }

      if afterUr.verify_token != "" {
        t.Fatalf("Expected verify_token to be blank, but it was %s", afterUr.verify_token)
      }

      if !afterUr.EmailVerified {
        t.Fatal("EmailVerified should be true")
      }
      t.Logf("  - email %s was verified successfully", ur.EmailAddr)
    }

    // The last case is saved in SavedRow
    SavedRow = ur

    if c.loginUser != "" {
      t.Log("  - logging out")
      // logout
      doLogoutCase(&logoutCase{"Correct logout", fmt.Sprintf(`{ "SessionToken":"%s", "Salt":"%s" }`, SavedSessionToken, SavedSessionSalt),
        fmt.Sprintf("Logout of SessionToken %s (1 row deleted)", SavedSessionToken[:8])}, t)
    }
  }

}

// Request body is not JSON
func Test_doUser_Bad_JSON(t *testing.T) {
  u, err := doTestUser(t, "", "{ I am not valid JSON }")
  if err != nil {
    t.FailNow()
  }
  if u.ValidationResult.Status == StatusOK {
    t.Errorf("Status %s returned, should have been invalid", u.ValidationResult.Status)
  }

  t.Log("Expecting a parsing error")
  const expect = "Could not decode the request"
  if expect != u.ValidationResult.Message[0:len(expect)] {
    t.Errorf("Bad validation result message: %s", u.ValidationResult.Message)
  }
}

// Table of doTestUser request that fail validation, along with their expected error message
type validationCase struct {
  request     string
  expect      Result
  description string
}

func Test_AddUser_validation(t *testing.T) {

  var cases []validationCase = []validationCase{
    {`{ "EmailAddr": "", "UserId": "JDoe99", "FirstName": "Jane", "LastName": "Doe", "TzName": "America/Los_Angeles", "ClearPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ", "ConfirmPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ", "ValidationResult": { "Status": "", "Message":"", "SystemRef":"", "PropInError":"", "PropErrorMsg":"" }}`,
      Result{StatusInvalid, "Data validation failed", "", "EmailAddr", "Missing data"},
      "EmailAddr is required"},
    {`{ "EmailAddr": "invalid string", "UserId": "JDoe99", "FirstName": "Jane", "LastName": "Doe", "TzName": "America/Los_Angeles", "ClearPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ", "ConfirmPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ", "ValidationResult": { "Status": "", "Message":"", "SystemRef":"" }}`,
      Result{StatusInvalid, "Data validation failed", "", "EmailAddr", "Not a valid email address"},
      "EmailAddr needs to match a pattern"},
    {`{ "EmailAddr": "agentX@mailbot.net", "UserId": "agentY@mailbot.net", "FirstName": "Jane", "LastName": "Doe", "TzName": "America/Los_Angeles", "ClearPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ", "ConfirmPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  "}`,
      Result{StatusInvalid, "Data validation failed", "", "UserId", "Must match email address if it contains @"},
      "UserId must match email if it contains @"},
    {`{ "EmailAddr": "someone@mailbot.net", "UserId": "", "FirstName": "Jane", "LastName": "Doe", "TzName": "America/Los_Angeles", "ClearPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ", "ConfirmPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  "}`,
      Result{StatusInvalid, "Data validation failed", "", "UserId", "Missing data"},
      "UserId is required"},
    {`{ "EmailAddr": "someone@mailbot.net", "UserId": "JDoe99", "FirstName": "", "LastName": "Doe", "TzName": "America/Los_Angeles", "ClearPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ", "ConfirmPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  "}`,
      Result{StatusInvalid, "Data validation failed", "", "FirstName", "Missing data"},
      "FirstName is required"},
    {`{ "EmailAddr": "someone@mailbot.net", "UserId": "JDoe99", "FirstName": "Jane", "LastName": "", "TzName": "America/Los_Angeles", "ClearPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ", "ConfirmPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  "}`,
      Result{StatusInvalid, "Data validation failed", "", "LastName", "Missing data"},
      "LastName is required"},
    {`{ "EmailAddr": "someone@mailbot.net", "UserId": "JDoe99", "FirstName": "Jane", "LastName": "Doe", "TzName": "America/Los_Angeles", "ClearPassword": "", "ConfirmPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  "}`,
      Result{StatusInvalid, "Data validation failed", "", "ClearPassword", "Missing data"},
      "EmailAddr is required"},
    {`{ "EmailAddr": "someone@mailbot.net", "UserId": "JDoe99", "FirstName": "Jane", "LastName": "Doe", "TzName": "America/Los_Angeles", "ClearPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ", "ConfirmPassword": ""}`,
      Result{StatusInvalid, "Data validation failed", "", "ConfirmPassword", "Missing data"},
      "ConfirmPassword is required"},
    {`{ "EmailAddr": "someone@mailbot.net", "UserId": "JDoe99", "FirstName": "Jane", "LastName": "Doe", "TzName": "America/Los_Angeles", "ClearPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ", "ConfirmPassword": "notmatching"}`,
      Result{StatusInvalid, "Data validation failed", "", "ConfirmPassword", "Passwords did not match"},
      "ConfirmPassword must match ClearPassword"},
    {`{ "EmailAddr": "someone@mailbot.net", "UserId": "JDoe99", "FirstName": "Jane", "LastName": "Doe", "TzName": "America/Los_Angeles", "ClearPassword": "123456789", "ConfirmPassword": "123456789"}`,
      Result{StatusInvalid, "Data validation failed", "", "ClearPassword", "Too short, at least 10 chars"},
      "Passwords at least 10 chars"},
    {`{ "EmailAddr": "someone@mailbot.net", "UserId": "JDoe99", "FirstName": "Jeff", "LastName": "Doe", "TzName": "", "ClearPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ", "ConfirmPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  "}`,
      Result{StatusInvalid, "Data validation failed", "", "TzName", "Missing data"},
      "TzName is required"},
    {`{ "EmailAddr": "someone@mailbot.net", "UserId": "JDoe99", "FirstName": "Jeff", "LastName": "Doe", "TzName": "ETC", "ClearPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ", "ConfirmPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  "}`,
      Result{StatusInvalid, "Data validation failed", "", "TzName", "Invalid time zone name"},
      "TzName must be on table"},
    {`{ "EmailAddr": "gmurray1966@gmail.com", "UserId": "NotJDoe99", "FirstName": "Jeff", "LastName": "Doe", "TzName": "America/Los_Angeles", "ClearPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ", "ConfirmPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  "}`,
      Result{StatusInvalid, "Data validation failed", "", "EmailAddr", "Already associated with a user"},
      "EmailAddr already associated"},
    {`{ "EmailAddr": "someone@mailbot.net", "UserId": "smithyrules!", "FirstName": "Jeff", "LastName": "Doe", "TzName": "America/New_York", "ClearPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  ", "ConfirmPassword": "  \u0009ODd-Pas{}[ ]( )*\\Re\"d/\\s  "}`,
      Result{StatusInvalid, "Data validation failed", "", "UserId", "Not available"},
      "UserId must be available"},
  }

  for i := 0; i < len(cases); i++ {
    auResp, err := doTestUser(t, "", cases[i].request)
    if err != nil {
      t.FailNow()
    }

    e := cases[i].expect
    t.Logf("Case %d: %s", i, cases[i].description)

    // check ValidationResult === expect
    if auResp.ValidationResult.Status != e.Status {
      t.Errorf("ERROR Status %s returned, expected %s", auResp.ValidationResult.Status, e.Status)
    }

    if auResp.ValidationResult.Message != e.Message {
      t.Errorf("ERROR Message \"%s\" returned, expected \"%s\"", auResp.ValidationResult.Message, e.Message)
    }

    if auResp.ValidationResult.PropInError != e.PropInError {
      t.Errorf("ERROR Property in error was \"%s\", but expected it to be \"%s\"", auResp.ValidationResult.PropInError, e.PropInError)
    }

    if auResp.ValidationResult.PropErrorMsg != e.PropErrorMsg {
      t.Errorf("ERROR Property error message was \"%s\", but expected it to be \"%s\"", auResp.ValidationResult.PropErrorMsg, e.PropErrorMsg)
    }

  }
}

type verificationCase struct {
  EmailAddr string
  Token     string
  Expected  Result
}

func expectResult(expect, actual Result, t *testing.T) {

  if actual.Status != expect.Status {
    t.Errorf("Result.Status: expected %s, actual %s", expect.Status, actual.Status)
  }

  if actual.Message != expect.Message {
    t.Errorf("Result.Message: expected %s, actual %s", expect.Message, actual.Message)
  }

  if actual.PropInError != expect.PropInError {
    t.Errorf("Result.PropInError expected %s, actual %s", expect.PropInError, actual.PropInError)
  }

  if actual.PropErrorMsg != expect.PropErrorMsg {
    t.Errorf("Result.PropErrorMsg expected %s, actual %s", expect.PropErrorMsg, actual.PropErrorMsg)
  }
}

func Test_EmailAddr_Verification_Failures(t *testing.T) {

  const typicalMessage = "Verification failed"
  cases := []verificationCase{
    {"WTF-Email", "6ba7b814-9dad-11d1-80b4-00c04fd430c8", Result{StatusInvalid, typicalMessage, "", "EmailAddr", "Not a valid email address"}},
    {"matches@pattern.io", "toktok", Result{StatusInvalid, typicalMessage, "", "Token", "Not a valid token"}},
    {"matches@pattern.io", "6ba7b814-9dad-11d1-80b4-00c04fd430c8", Result{StatusInvalid, typicalMessage, "", "", ""}},
  }

  for c := 0; c < len(cases); c++ {
    cur := cases[c]
    t.Logf("Case %d: EmailAddr=%s Token=%s", c, cur.EmailAddr, cur.Token)

    vr, err := verifyEmailTest(cur.EmailAddr, cur.Token, t)
    if err != nil {
      t.Fatalf("Unexpected error while verifying: %s", err)
    }

    expectResult(cur.Expected, vr.ValidationResult, t)
  }
}

func doTestLogin(t *testing.T, body string) (r *LoginResponse, err error) {

  client := initClient()
  r = new(LoginResponse)

  c1 := strings.NewReader(body)

  addr := fmt.Sprintf("%s:%d", Conf.HttpsHost, Conf.HttpsPort)
  req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/session/login", addr), c1)
  req.Header.Set("User-Agent", SavedUserAgent)
  if err != nil {
    t.Fatalf("Failed to create a request: %s", err)
    return r, err
  }

  resp, err := client.Do(req)
  if err != nil {
    t.Fatalf("client request failed: %s", err)
    return r, err
  }

  SavedCookieJar, err = cookiejar.New(nil)
  if err != nil {
    t.Fatalf("Cookiejar is broken: %s", err)
  }

  u, err := url.Parse(fmt.Sprintf("https://%s/", addr))
  if err != nil {
    t.Fatalf("Could not parse url: %s", err)
  }

  SavedCookieJar.SetCookies(u, resp.Cookies())

  dec := json.NewDecoder(resp.Body)

  err = dec.Decode(r)
  if err != nil {
    t.Fatalf("Error while decoding response body: %s", err)
  }

  return r, err
}

// Request body is not JSON
func Test_Login_Bad_JSON(t *testing.T) {
  r, err := doTestLogin(t, "{ I am not valid JSON }")
  if err != nil {
    t.FailNow()
  }
  if r.ValidationResult.Status == StatusOK {
    t.Errorf("Status %s returned, should have been invalid", r.ValidationResult.Status)
  }

  t.Log("Expecting a parsing error")
  const expect = "Could not decode the request"
  if expect != r.ValidationResult.Message[0:len(expect)] {
    t.Errorf("Bad validation result message: %s", r.ValidationResult.Message)
  }
}

type loginCase struct {
  desc          string
  bod           string
  expect        Result
  expectSuccess bool // true: case is expected to succeed, false: case expected to false
  expectLogMsg  string
}

func loginCaseFactory(index int) *loginCase {

  switch index {
  case 0:
    return &loginCase{"UserIdentifier is required", `{"UserIdentifier":"", "ClearPassword":"password"}`, Result{StatusInvalid, "Authentication failed", "", "UserIdentifier", "Missing data"}, false, "blank user identifier"}
  case 1:
    return &loginCase{"ClearPassword is required", `{"UserIdentifier":"loser", "ClearPassword":""}`, Result{StatusInvalid, "Authentication failed", "", "ClearPassword", "Missing data"}, false, "blank password"}
  case 2:
    return &loginCase{"Correct SysUserId with bad password", fmt.Sprintf(`{"UserIdentifier":"  %s", "ClearPassword":"bad"}`, strings.ToUpper(SavedRow.SysUserId)), Result{StatusInvalid, "Authentication failed", "", "", ""}, false, "passwords did not match"}
  case 3:
    return &loginCase{"Correct UserId with bad password", fmt.Sprintf(`{"UserIdentifier":" %s ", "ClearPassword":"bad"}`, SavedRow.UserId), Result{StatusInvalid, "Authentication failed", "", "", ""}, false, "passwords did not match"}
  case 4:
    return &loginCase{"Correct EmailAddr with bad password", fmt.Sprintf(`{"UserIdentifier":"%s  ", "ClearPassword":"bad"}`, SavedRow.EmailAddr), Result{StatusInvalid, "Authentication failed", "", "", ""}, false, "passwords did not match"}
  case 5:
    return &loginCase{"UserIdentifier is EmailAddr", fmt.Sprintf(`{"UserIdentifier":"%s  ", "ClearPassword":"%s"}`, SavedRow.EmailAddr, SavedClearPassword), Result{StatusOK, "Authentication successful", "", "", ""}, true, fmt.Sprintf("using password for SysUserId %s", SavedRow.SysUserId)}
  case 6:
    return &loginCase{"UserIdentifier is SysUserId", fmt.Sprintf(`{"UserIdentifier":"%s  ", "ClearPassword":"%s"}`, SavedRow.SysUserId, SavedClearPassword), Result{StatusOK, "Authentication successful", "", "", ""}, true, fmt.Sprintf("using password for SysUserId %s", SavedRow.SysUserId)}
  case 7:
    return &loginCase{"UserIdentifier is UserId", fmt.Sprintf(`{"UserIdentifier":"%s  ", "ClearPassword":"%s"}`, SavedRow.UserId, SavedClearPassword), Result{StatusOK, "Authentication successful", "", "", ""}, true, fmt.Sprintf("using password for SysUserId %s", SavedRow.SysUserId)}
  case 8:
    return &loginCase{"SessionToken is not UUID", fmt.Sprintf(`{"UserIdentifier":"%s", "SessionToken":"wtf", "Salt":""}`, SavedRow.SysUserId), Result{StatusInvalid, "Authentication failed", "", "SessionToken", "Invalid data"}, false, "Error during SelectValidSession call: SessionToken (wtf) is not a UUID"}
  case 9:
    return &loginCase{"Salt is missing", fmt.Sprintf(`{"UserIdentifier":"%s", "SessionToken":"6ba7b814-9dad-11d1-80b4-00c04fd430c8", "Salt":""}`, SavedRow.SysUserId), Result{StatusInvalid, "Authentication failed", "", "SessionToken", "Invalid data"}, false, "Error during SelectValidSession call: Salt is missing"}
  case 10:
    return &loginCase{"Salt is unparsable", fmt.Sprintf(`{"UserIdentifier":"%s", "SessionToken":"6ba7b814-9dad-11d1-80b4-00c04fd430c8", "Salt":"wtf-wtf-wtf-wtf-wtf-wtf-wtf-wtf-wtf-wtf-wtf-wtf-wtf-wtf-wtf-wtf-"}`, SavedRow.SysUserId), Result{StatusInvalid, "Authentication failed", "", "SessionToken", "Invalid data"}, false, "Error during SelectValidSession call: Encryption failed: encoding/hex: invalid byte: U+0077"}
  case 11:
    return &loginCase{"Salt is too long", fmt.Sprintf(`{"UserIdentifier":"%s", "SessionToken":"6ba7b814-9dad-11d1-80b4-00c04fd430c8", "Salt":"00c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c800c04fd430c8"}`, SavedRow.SysUserId), Result{StatusInvalid, "Authentication failed", "", "SessionToken", "Invalid data"}, false, "Error during SelectValidSession call: Salt must be 32 bytes but was 132 bytes"}
  case 12:
    return &loginCase{"Happy path with SessionToken and SysUserId", fmt.Sprintf(`{"UserIdentifier":"%s", "SessionToken":"%s", "Salt":"%s"}`, SavedRow.SysUserId, SavedSessionToken, SavedSessionSalt), Result{StatusOK, "Authentication successful", "", "", ""}, true, fmt.Sprintf("Session %s using token for SysUserId %s", SavedSessionToken[:8], SavedRow.SysUserId)}
  case 13:
    return &loginCase{"Happy path with SessionToken and UserId", fmt.Sprintf(`{"UserIdentifier":"%s", "SessionToken":"%s", "Salt":"%s"}`, SavedRow.UserId, SavedSessionToken, SavedSessionSalt), Result{StatusOK, "Authentication successful", "", "", ""}, true, fmt.Sprintf("Session %s using token for SysUserId %s", SavedSessionToken[:8], SavedRow.SysUserId)}
  case 14:
    return &loginCase{"login_allowed = false", fmt.Sprintf(`{"UserIdentifier":"%s  ", "ClearPassword":"%s"}`, SavedRow.UserId, SavedClearPassword), Result{StatusInvalid, "Login is not permitted", "", "", ""}, false, "login not permitted"}
  case 15:
    return &loginCase{"EmailVerified = false", fmt.Sprintf(`{"UserIdentifier":"%s  ", "ClearPassword":"%s"}`, SavedRow.UserId, SavedClearPassword), Result{StatusInvalid, "Login is not permitted with unverified email address. Email was sent to gmurray1966@gmail.com", "", "", ""}, false, "login not permitted with unverified email"}
  default:
    return nil
  }
  return nil
}

func doLoginCase(cur *loginCase, t *testing.T) {

  r, err := doTestLogin(t, cur.bod)
  if err != nil {
    t.FailNow()
  }

  if r.ValidationResult.Status == StatusOK {
    SavedSessionToken = r.SessionToken
    SavedSessionSalt = r.Salt
  }

  e := cur.expect

  // check ValidationResult === expect
  if r.ValidationResult.Status != e.Status {
    t.Errorf("ERROR Status %s returned, expected %s", r.ValidationResult.Status, e.Status)
  }

  if r.ValidationResult.Message != e.Message {
    t.Errorf("ERROR Message \"%s\" returned, expected \"%s\"", r.ValidationResult.Message, e.Message)
  }

  if r.ValidationResult.PropInError != e.PropInError {
    t.Errorf("ERROR Property in error was \"%s\", but expected it to be \"%s\"", r.ValidationResult.PropInError, e.PropInError)
  }

  if r.ValidationResult.PropErrorMsg != e.PropErrorMsg {
    t.Errorf("ERROR Property error message was \"%s\", but expected it to be \"%s\"", r.ValidationResult.PropErrorMsg, e.PropErrorMsg)
  }

  if cur.expectSuccess && r.SessionTTL != Conf.SessionTimeout {
    t.Errorf("ERROR Missing or invalid SessionTTL (%d) returned", r.SessionTTL)
  }

  if cur.expectSuccess {
    vResp := VerifyIdentity(cur.desc, r.SysUserId, ClearSessionId{SessionToken: SavedSessionToken, Salt: SavedSessionSalt}, SavedIpAddress, SavedUserAgent)
    if vResp.ValidationResult.Status != StatusOK {
      t.Fatalf("Verify failed")
    }
  } else {
    if r.SessionToken != "" {
      t.Errorf("ERROR SessionToken should have been blank but was: %s", r.SessionToken)
    }

    if r.Salt != "" {
      t.Errorf("ERROR Salt should have been blank but was: %s", r.Salt)
    }
    if r.SessionTTL != 0 {
      t.Errorf("ERROR SessionTTL should have been 0 but was: %d", r.SessionTTL)
    }
    if r.SysUserId != "" {
      t.Errorf("ERROR SysUserId should have been blank but was: %s", r.SysUserId)
    }
    if r.UserId != "" {
      t.Errorf("ERROR UserId should have been blank but was: %s", r.UserId)
    }
    if r.EmailAddr != "" {
      t.Errorf("ERROR EmailAddr should have been blank but was: %s", r.EmailAddr)
    }
    if r.FirstName != "" {
      t.Errorf("ERROR FirstName should have been blank but was: %s", r.FirstName)
    }
    if r.LastName != "" {
      t.Errorf("ERROR LastName should have been blank but was: %s", r.LastName)
    }
    if r.TzName != "" {
      t.Errorf("ERROR TzName should have been blank but was: %s", r.TzName)
    }
  }

  mustExistInLog(r.ValidationResult.SystemRef, cur.expectLogMsg, t)
}

func Test_Login_table(t *testing.T) {

  const tempToken = "6ba7b814-9dad-11d1-80b4-00c04fd430c8"

  for i := 0; i < 1000; i++ {
    cur := loginCaseFactory(i)
    if cur == nil {
      break
    }

    t.Logf("Case %d: %s", i, cur.desc)

    if i == 14 {
      _, err := Conf.DatabaseHandle.Exec("update session.user set login_allowed = false where SysUserId = $1", SavedRow.SysUserId)
      if err != nil {
        t.Fatalf("Failed to updated login_allowed: %s", err)
      }
    }

    if i == 15 {
      _, err := Conf.DatabaseHandle.Exec("update session.user set EmailVerified = false, verify_token = $1 where SysUserId = $2", tempToken, SavedRow.SysUserId)
      if err != nil {
        t.Fatalf("Failed to updated login_allowed: %s", err)
      }
    }

    doLoginCase(cur, t)

    if i == 15 {
      // process the email verification
      compareEmailValues(SavedRow.EmailAddr, tempToken, t)
    }

    if i == 14 {
      _, err := Conf.DatabaseHandle.Exec("update session.user set login_allowed = true where SysUserId = $1", SavedRow.SysUserId)
      if err != nil {
        t.Fatalf("Failed to updated login_allowed: %s", err)
      }
    }
  }
}

// mustExistInLog finds lines in the logfile containing both prefix and expectStr
// if it is not found the test is failed
func mustExistInLog(prefix string, expectStr string, t *testing.T) {

  logf, err := os.Open(LOGFILENAME)
  if err != nil {
    t.Fatalf("Log file %s could not be opened: %s", LOGFILENAME, err)
  }
  defer logf.Close()

  found := false
  scanner := bufio.NewScanner(logf)
  for scanner.Scan() {
    line := scanner.Text()
    if strings.Contains(line, prefix) && strings.Contains(line, expectStr) {
      found = true
      break
    }
  }
  if err := scanner.Err(); err != nil {
    t.Fatalf("Error while reading logfile: %s", err)
  }

  if !found {
    t.Fatalf("Failed to find in logfile (%s && &s)", prefix, expectStr)
  }

}

type logoutCase struct {
  desc   string
  req    string
  expect string
}

func doLogoutCase(cur *logoutCase, t *testing.T) {

  client := initClient()

  c1 := strings.NewReader(cur.req)

  addr := fmt.Sprintf("%s:%d", Conf.HttpsHost, Conf.HttpsPort)
  req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/session/logout", addr), c1)
  if err != nil {
    t.Fatalf("Failed to create a request: %s", err)
  }

  req.Header.Set("User-Agent", SavedUserAgent)
  resp, err := client.Do(req)
  if err != nil {
    t.Fatalf("client request failed: %s", err)
  }

  dec := json.NewDecoder(resp.Body)

  r := new(struct {
    SystemRef string
  })

  err = dec.Decode(r)
  if err != nil {
    t.Fatalf("Error while decoding response body: %s", err)
  }

  mustExistInLog(r.SystemRef, cur.expect, t)
}

func Test_Logout_table(t *testing.T) {

  if SavedSessionToken == "" {
    t.Fatal("Ooops SavedSessionToken is blank")
  }

  cases := []logoutCase{
    {"Meaningless JSON", `{ "JunkProperty":"doh" }`, "Invalid logout request received: Failed to encrypt SessionToken: SessionToken () is not a UUID"},
    {"Blank session token", `{ "SessionToken":"" }`, "Invalid logout request received: Failed to encrypt SessionToken: SessionToken () is not a UUID"},
    {"Non-uuid session token", `{ "SessionToken":"doh" }`, "Invalid logout request received: Failed to encrypt SessionToken: SessionToken (doh) is not a UUID"},
    {"Missing Salt", `{ "SessionToken":"6ba7b810-9dad-11d1-80b4-00c04fd430c8" }`, "Invalid logout request received: Failed to encrypt SessionToken: Salt is missing"},
    {"Blank Salt", `{ "SessionToken":"6ba7b810-9dad-11d1-80b4-00c04fd430c8", "Salt":"" }`, "Invalid logout request received: Failed to encrypt SessionToken: Salt is missing"},
    {"Unparsable Salt", `{ "SessionToken":"6ba7b810-9dad-11d1-80b4-00c04fd430c8", "Salt":"doh!doh!doh!doh!doh!doh!doh!doh!doh!doh!doh!doh!doh!doh!doh!doh!" }`, "Invalid logout request received: Failed to encrypt SessionToken: Encryption failed: encoding/hex: invalid byte: U+006F"},
    {"Incorrect length Salt", `{ "SessionToken":"6ba7b810-9dad-11d1-80b4-00c04fd430c8", "Salt":"abcd" }`, "Invalid logout request received: Failed to encrypt SessionToken: Salt must be 32 bytes but was 2 bytes"},
    {"Not in database", `{ "SessionToken":"6ba7b810-9dad-11d1-80b4-00c04fd430c8", "Salt":"abcdabcdabcdabcdabcdabcdabcdabcdabcd00112233445566778899aabbccdd" }`, "No such session 6ba7b810 to delete"},
    {"Right session token, wrong Salt", fmt.Sprintf(`{ "SessionToken":"%s", "Salt":"abcdabcdabcdabcdabcdabcdabcdabcdabcd00112233445566778899aabbccdd" }`, SavedSessionToken),
      fmt.Sprintf("No such session %s to delete", SavedSessionToken[:8])},
    {"Right Salt, wrong session token", fmt.Sprintf(`{ "SessionToken":"6ba7b810-9dad-11d1-80b4-00c04fd430c8", "Salt":"%s" }`, SavedSessionSalt), "No such session 6ba7b810 to delete"},
    {"Correct logout", fmt.Sprintf(`{ "SessionToken":"%s", "Salt":"%s" }`, SavedSessionToken, SavedSessionSalt),
      fmt.Sprintf("Logout of SessionToken %s (1 row deleted)", SavedSessionToken[:8])},
    {"Re-logout", fmt.Sprintf(`{ "SessionToken":"%s", "Salt":"%s" }`, SavedSessionToken, SavedSessionSalt),
      fmt.Sprintf("No such session %s to delete", SavedSessionToken[:8])},
  }

  for i := 0; i < len(cases); i++ {
    c := cases[i]
    t.Logf("Case %d: %s", i, c.desc)
    doLogoutCase(&c, t)
  }
}

func doResetPassword(t *testing.T, inEmailAddr, expectLogMsg string) {

  client := initClient()
  r := new(struct {
    SystemRef string
  })

  addr := fmt.Sprintf("%s:%d", Conf.HttpsHost, Conf.HttpsPort)
  req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/session/reset/%s", addr, inEmailAddr), nil)
  req.Header.Set("User-Agent", SavedUserAgent)
  if err != nil {
    t.Fatalf("Failed to create a request: %s", err)
  }

  resp, err := client.Do(req)
  if err != nil {
    t.Fatalf("client request failed: %s", err)
  }

  _, err = url.Parse(fmt.Sprintf("https://%s/", addr))
  if err != nil {
    t.Fatalf("Could not parse url: %s", err)
  }

  dec := json.NewDecoder(resp.Body)

  err = dec.Decode(r)
  if err != nil {
    t.Fatalf("Error while decoding response body: %s", err)
  }

  mustExistInLog(r.SystemRef, expectLogMsg, t)
}

func useResetTokenInEmail(t *testing.T, inEmailAddr string) *LoginResponse {
  // get the token from the email and use it
  bod, err := getEmail(inEmailAddr)
  if err != nil {
    t.Fatalf("getEmail returned an error: %s", err)
  }

  // parse out the link to get email address and token
  s1 := bod[strings.Index(bod, "reset/")+6:] // s1 starts at email address
  EmailAddr := s1[:strings.Index(s1, "/")]
  s2 := bod[strings.Index(bod, "token/")+6:] // s2 starts at the token value
  ResetToken := s2[:strings.Index(s2, "\n")]

  // Use the token by getting the link
  lr, err := resetEmailTest(EmailAddr, ResetToken, t)
  if err != nil {
    t.Fatalf("Unexpected error while resetting: %s", err)
  }

  return lr
}

// tests url /session/reset/  (i.e. blank email address)
func Test_doReset_blank_EmailAddress(t *testing.T) {

  client := initClient()
  addr := fmt.Sprintf("%s:%d", Conf.HttpsHost, Conf.HttpsPort)
  req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/session/reset/", addr), nil)
  req.Header.Set("User-Agent", SavedUserAgent)
  if err != nil {
    t.Fatalf("Failed to create a request: %s", err)
  }

  resp, err := client.Do(req)
  if err != nil {
    t.Fatalf("client request failed: %s", err)
  }

  if resp.StatusCode != http.StatusNotFound {
    t.Fatalf("HTTP status: expected %s, actual %d", http.StatusNotFound, resp.StatusCode)
  }
}

// tests url /session/reset/{em}/token/ (i.e. blank token)
func Test_useReset_blank_token(t *testing.T) {

  client := initClient()
  addr := fmt.Sprintf("%s:%d", Conf.HttpsHost, Conf.HttpsPort)
  req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/session/reset/someone@somewhere.net/token/", addr), nil)
  req.Header.Set("User-Agent", SavedUserAgent)
  if err != nil {
    t.Fatalf("Failed to create a request: %s", err)
  }

  resp, err := client.Do(req)
  if err != nil {
    t.Fatalf("client request failed: %s", err)
  }

  if resp.StatusCode != http.StatusNotFound {
    t.Fatalf("HTTP status: expected %s, actual %d", http.StatusNotFound, resp.StatusCode)
  }
}

// Reset email address does not match the email pattern
func Test_doReset_fail_bad_address(t *testing.T) {
  doResetPassword(t, "bad-address", "Password reset for bad-address failed, bad email address")
}

// Email address is not in database
func Test_doReset_fail_unknown_address(t *testing.T) {
  doResetPassword(t, "notfound@here.com", "SelectUser err: sql: no rows in result set")
}

func Test_doReset_on_already_reset(t *testing.T) {

  if SavedRow == nil {
    t.Fatal("SavedRow failed to save in previous test")
  }

  doResetPassword(t, SavedRow.EmailAddr, "Created a reset token for email addess "+SavedRow.EmailAddr)

  ur, err := SelectUser(SavedRow.EmailAddr)
  if err != nil {
    t.Fatalf("SelectUser returned with error: %s", err)
  }

  SavedRow = ur // update the SavedRow

  // We now have a user who has requested a password reset

  doResetPassword(t, SavedRow.EmailAddr, "Active reset token already exists for "+SavedRow.EmailAddr)
}

func Test_doReset_on_expired_reset(t *testing.T) {
  // Assert: have a user (SavedRow) who has requested a password reset from previous test

  // force the expiration of the token
  err := SavedRow.expireResetToken()
  if err != nil {
    t.Fatalf("expireResetToken returned with error: %s", err)
  }

  oldResetToken := SavedRow.reset_token

  // get the email to clear all emails
  _, err = getEmail(SavedRow.EmailAddr)
  if err != nil {
    t.Fatalf("getEmail returned an error: %s", err)
  }

  doResetPassword(t, SavedRow.EmailAddr, "Created a reset token for email addess "+SavedRow.EmailAddr)

  ur, err := SelectUser(SavedRow.EmailAddr)
  if err != nil {
    t.Fatalf("SelectUser returned with error: %s", err)
  }

  SavedRow = ur // update the SavedRow

  if oldResetToken == SavedRow.reset_token {
    t.Fatalf("Expected a fresh reset token, but got the expired one")
  }
}

func Test_useReset_success(t *testing.T) {
  lr := useResetTokenInEmail(t, SavedRow.EmailAddr)

  tok := SavedCookieMap["SessionToken"].Value
  salt := SavedCookieMap["Salt"].Value

  if len(tok) != 36 {
    t.Fatalf("Expected SessionToken length 36, actual %d", len(tok))
  }

  if len(salt) != 64 {
    t.Fatalf("Expected Salt length 64, actual %d", len(salt))
  }

  sess, err := SelectValidSession(&ClearSessionId{tok, salt})
  if err != nil {
    t.Fatalf("SelectValidSession returned error: %s", err)
  }
  t.Logf("SessionToken=%s\n  expires: %s\n  started: %s", tok, sess.expires_dt, sess.start_dt)

  if len(SavedCookieMap["SysUserId"].Value) != 36 {
    t.Fatalf("Expected SysUserId length 36, actual %d", len(SavedCookieMap["SysUserId"].Value))
  }

  if lr.ValidationResult.Status != StatusOK {
    t.Errorf("Expected OK status after verification but got=%s", lr.ValidationResult.Status)
  }

  expectResult(Result{Status: StatusOK, Message: "Reset request is valid", PropInError: "", PropErrorMsg: ""}, lr.ValidationResult, t)
  mustExistInLog(lr.ValidationResult.SystemRef, fmt.Sprintf("Reset request is valid for email %s", SavedRow.EmailAddr), t)

  // check fields updated: reset_token, EmailVerified, verify_token
  ur, err := SelectUser(SavedRow.EmailAddr)
  if err != nil {
    t.Fatalf("SelectUser returned with error: %s", err)
  }
  SavedRow = ur // update the SavedRow

  if SavedRow.reset_token != "" {
    t.Fatal("Expected reset_token to be blank")
  }

  if SavedRow.verify_token != "" {
    t.Fatal("Expected verify_token to be blank")
  }

  if !SavedRow.EmailVerified {
    t.Fatal("Expected EmailVerified to be true")
  }
}

func Test_useReset_token_is_not_UUID(t *testing.T) {

  lr, err := resetEmailTest(SavedRow.EmailAddr, "not_real_token", t)
  if err != nil {
    t.Fatalf("Unexpected error while resetting: %s", err)
  }

  expectResult(Result{Status: StatusInvalid, Message: "Reset failed", PropInError: "ResetToken", PropErrorMsg: "Not a valid reset token"}, lr.ValidationResult, t)

}

func Test_useReset_token_is_not_in_db(t *testing.T) {

  lr, err := resetEmailTest(SavedRow.EmailAddr, "4acc6c82-667c-4e4b-6a52-d5dfdc188007", t)
  if err != nil {
    t.Fatalf("Unexpected error while resetting: %s", err)
  }

  expectResult(Result{Status: StatusInvalid, Message: "Reset failed", PropInError: "", PropErrorMsg: ""}, lr.ValidationResult, t)
  mustExistInLog(lr.ValidationResult.SystemRef, "No reset token in database", t)

}

func Test_useReset_on_expired_reset(t *testing.T) {
  doResetPassword(t, SavedRow.EmailAddr, "Created a reset token for email addess "+SavedRow.EmailAddr)

  // force the expiration of the token
  err := SavedRow.expireResetToken()
  if err != nil {
    t.Fatalf("expireResetToken returned with error: %s", err)
  }

  lr := useResetTokenInEmail(t, SavedRow.EmailAddr)

  expectResult(Result{Status: StatusInvalid, Message: "Reset failed", PropInError: "", PropErrorMsg: ""}, lr.ValidationResult, t)
  mustExistInLog(lr.ValidationResult.SystemRef, "Reset token is expired", t)
}

func Test_doReset_login_disallowed(t *testing.T) {
  err := SavedRow.setLoginAllowed(false)
  if err != nil {
    t.Fatalf("setLoginAllowed returned with error: %s", err)
  }

  doResetPassword(t, SavedRow.EmailAddr, "login_allowed is false")

  err = SavedRow.setLoginAllowed(true)
  if err != nil {
    t.Fatalf("setLoginAllowed returned with error: %s", err)
  }
}

func Test_useReset_login_disallowed(t *testing.T) {
  // login_allowed should already be true, but make sure
  err := SavedRow.setLoginAllowed(true)
  if err != nil {
    t.Fatalf("setLoginAllowed returned with error: %s", err)
  }

  doResetPassword(t, SavedRow.EmailAddr, "Created a reset token for email addess "+SavedRow.EmailAddr)

  err = SavedRow.setLoginAllowed(false)
  if err != nil {
    t.Fatalf("setLoginAllowed returned with error: %s", err)
  }

  lr := useResetTokenInEmail(t, SavedRow.EmailAddr)

  expectResult(Result{Status: StatusInvalid, Message: "Reset failed", PropInError: "", PropErrorMsg: ""}, lr.ValidationResult, t)
  mustExistInLog(lr.ValidationResult.SystemRef, "login_allowed is false", t)

  err = SavedRow.setLoginAllowed(true)
  if err != nil {
    t.Fatalf("setLoginAllowed returned with error: %s", err)
  }
}
