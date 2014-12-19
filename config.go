package session

import (
  "bufio"
  "database/sql"
  "encoding/hex"
  "flag"
  "fmt"
  "code.grantmurray.com/mailbot"
  "github.com/golang/glog"
  _ "github.com/lib/pq"
  "os"
)

/* Config holds the values loaded from the database. The database dataSourceName is bootstrapped from standard input.
   Why store configuration in the database rather than other alternatives:
     1. Because any running service's configuration can be observered accurately (dubious reason)
     2. ALL data about the service is in ONE place only
     3. No special configuration file parser is needed
     4. Values can have their types enforced by the database
*/
type Config struct {
  // *** from standard input ***

  // DatabaseSource is the string used to open the PostgreSQL database
  DatabaseSource string

  // ServerKey is a secret used in hashing of passwords it
  // is not stored in the database because that would
  // diminish security
  ServerKey []byte // entered as hex digit string

  // *** from database table Session.config ***

  // SessionTimeout in number of seconds
  SessionTimeout int

  // SessionMaxLife in number of seconds, session forced to expire
  SessionMaxLife int

  // DatabaseHandle is here as a convenience since we have it and
  // it is deriviative of DatabaseSource and the only thing to do with
  // DatabaseSource is to open a connection
  DatabaseHandle *sql.DB

  // Smtp is the outgoing smtp config as needed by mailbot'
  Smtp mailbot.ServerConfig

  // VerifyTemplate is the text template used when sending the email
  // used to verify the email address of a new user
  VerifyTemplate string

  // ResetTemplate is the text template used when sending the email
  // to reset a password
  ResetTemplate string

  // PasswordResetExpirationDuration is the number of seconds that a reset token will be valid for
  PasswordResetExpiresDuration int

  // *** instance specific ***
  InstanceId string

  // Certificates and key that are needed to start an https server
  // (see create-test-certs.sh for some hints on loading these)
  HttpsKey  []byte
  HttpsCert []byte

  // HttpsHost is the address the server will listen on
  // for example: "plog.org"
  HttpsHost string

  // HttpsPort is the port that the server will listen on
  HttpsPort int
}

// Conf is a package global so that it is accessible everywhere.
var Conf *Config

// bootstrap sets DatabaseSource and ServerKey from stdin
func (c *Config) bootstrap() {

  var scanner *bufio.Scanner

  tfile, err := os.Open("/tmp/session_test.config.bootstrap.input")
  if err == nil {
    defer tfile.Close()
    scanner = bufio.NewScanner(tfile)
  } else {
    scanner = bufio.NewScanner(os.Stdin)
  }

  // DatabaseSource
  fmt.Print("Enter the PostgreSQL source string: ")
  scanner.Scan()
  c.DatabaseSource = scanner.Text()
  fmt.Println()

  // ServerKey
  fmt.Print("Enter the secret server key: ")
  scanner.Scan()
  sk := scanner.Text()
  fmt.Println()

  if err = scanner.Err(); err != nil {
    panic(fmt.Sprintf("Error reading input: %s", err))
  }

  c.ServerKey, err = hex.DecodeString(sk)
  if err != nil {
    panic(fmt.Sprintf("Failed to convert SERVERKEY [%s] to bytes: %s", sk, err))
  }

}

func init() {
  var err error

  Conf = new(Config)
  Conf.bootstrap()

  flag.StringVar(&Conf.InstanceId, "instance", "None", "An identifier for the instance, used to fetch the instance specific configuration")

  if len(Conf.ServerKey) != 64 {
    panic(fmt.Sprintf("Serverkey needs to be 64 bytes long exactly, it was only %d bytes", len(Conf.ServerKey)))
  }

  Conf.DatabaseHandle, err = sql.Open("postgres", Conf.DatabaseSource)
  if err != nil {
    panic(err)
  }
}

// Load reads configuration values from database tables and loads them into the global variable Conf.
func LoadConfig() {
  var err error

  // LoadConfig would ideally be done in init() but since loading depends on flag values it needs to be done after flag.Parse()
  if len(Conf.InstanceId) == 0 || Conf.InstanceId == "None" {
    panic("Command line parameter `instance` is missing, cannot complete config")
  }

  var iloaded bool = false
  rows, err := Conf.DatabaseHandle.Query("SELECT SessionTimeout, SessionMaxLife, SmtpServerHost, SmtpServerPort, SmtpFrom, SmtpAuthUsername, SmtpAuthPassword, VerifyTemplate, ResetTemplate, PasswordResetExpiresDuration FROM session.config")
  if err != nil {
    panic(err)
  }

  for rows.Next() {
    if err := rows.Scan(&Conf.SessionTimeout, &Conf.SessionMaxLife,
      &Conf.Smtp.Host, &Conf.Smtp.Port, &Conf.Smtp.EmailFrom, &Conf.Smtp.User, &Conf.Smtp.Password,
      &Conf.VerifyTemplate, &Conf.ResetTemplate, &Conf.PasswordResetExpiresDuration); err != nil {
      panic(err)
    }
    iloaded = true
  }
  if err := rows.Err(); err != nil {
    panic(err)
  }

  if !iloaded {
    panic("Configuration failed to load")
  }

  if glog.V(1) {
    glog.Info("Common configuration loaded from database")
  }

  iloaded = false
  rows, err = Conf.DatabaseHandle.Query("SELECT HttpsKey, HttpsCert, HttpsHost, HttpsPort FROM session.instconfig WHERE InstanceId = $1", Conf.InstanceId)
  if err != nil {
    panic(fmt.Sprintf("instance:%s, err:%s", Conf.InstanceId, err))
  }

  for rows.Next() {
    if err := rows.Scan(&Conf.HttpsKey, &Conf.HttpsCert, &Conf.HttpsHost, &Conf.HttpsPort); err != nil {
      panic(err)
    }
    iloaded = true
  }
  if err := rows.Err(); err != nil {
    panic(err)
  }

  if !iloaded {
    panic(fmt.Sprintf("Missing instance configuration for %s", Conf.InstanceId))
  }

  if glog.V(1) {
    glog.Info(fmt.Sprintf("Configuration for instance %s (%s:%d) loaded from database", Conf.InstanceId, Conf.HttpsHost, Conf.HttpsPort))
  }

  glog.Flush()
}
