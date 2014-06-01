% sessiond - authentication daemon

## Creating a user (by the user)

This is the case where a user creates her own user in the system. Sometimes this is called registering or "signing up". The only proof of identity the user provides is an email address that is under her control.

### Request
The HTTP method and URL is: PUT /session/users

No authenticated user context is required for this request.

Example:

    {
      "EmailAddr": "JaneDoe@Example.Org",
      "UserId": "JDoe99",
      "FirstName": "Jane",
      "LastName": "Doe",
      "TzName": "America/Los_Angeles",
      "ClearPassword": "big-secret-2000",
      "ConfirmPassword": "big-secret-2000"
    }

EmailAddr
:   Value is a mutable unique identifier.

    Value is case insensitive, stored as lower case.

    Value has leading and trailing spaces removed.

    Value conforms to a simple pattern, viz: [^@]+?@.{2,128}\.[a-z]{2,44}
    

UserId
:   Value is a mutable unique identifier.

    Value is case insensitive, stored as lower case.
    
    Value has leading and trailing spaces removed.
    

FirstName
:   Value has leading and trailing spaces removed.

LastName
:   Value has leading and trailing spaces removed.

TzName
:   A string identifying the user's home time zone.
    
    Values are a subset of pg_timezone_names.

ClearPassword
:   The password as supplied by the user.
    
    Its form is unrestrictive. Leading and trailing space is significant. It can contain "special" characters.
    
    Value is at least 10 characters long.

ConfirmPassword
:   Value is identical to ClearPassword.

### Processing
The ClearPassword is salted and stored encrypted using the [scrypt algorithm][scrypt].

A personalized email message is sent to the provided EmailAddr. The message contains a single use token embedded in a URL, **/session/user/{EmailAddr}/token/{Token}**. When the URL is visited (GET) by the user, the EmailAddr becomes verified.

An immutable, UUID called SysUserId is created.

### Future Enhancements

* Send an email to the administrator, when a new user registers. This obviously would only be switched on for cases where the userbase is small. Some method of identifying the administrator would be needed.

### Response {#Create-User-Response}
Example:

    {
      "SysUserId":"82d21795-29eb-4f51-5343-3433aee2c53a",
      "ValidationResult":
        {
          "Status":"OK",
          "Message":"New user registered successfully",
          "SystemRef":"doUser-069599:",
          "PropInError":"",
          "PropErrorMsg":""
        }
    }

SysUserId
:   Value is the UUID of the user just created.

ValidationResult
:   See [ValidationResult](#ValidationResult)

## Creating a user (by an administrator)

Not implemented.

How is this feature different from a user creating herself?

* Setting the password.
* The administrator would need to be logged in and authorized
* Different email verificatin template

## Updating a user

### Request

The HTTP method and URL is: POST /session/user/{SysUserId}

Example:

    {
      "SysUserId":"82d21795-29eb-4f51-5343-3433aee2c53a",
      "EmailAddr": "JaneDoe@Example.Org",
      "UserId": "JDoe99",
      "FirstName": "Jane",
      "LastName": "Doe",
      "TzName": "America/Los_Angeles",
      "ClearPassword": "big-secret-2000",
      "ConfirmPassword": "big-secret-2000"
    }

SysUserId
:   Value is the immutable UUID identifying the user to change.

EmailAddr
:   (Same validation as Creating new user.)

UserId
:   (Same validation as Creating new user.)

FirstName
:   (Same validation as Creating new user.)

LastName
:   (Same validation as Creating new user.)

TzName
:   (Same validation as Creating new user.)
    
ClearPassword
:   New password as supplied by the user.

    (Same form as Creating new user.)

    Blank is a valid value, meaning no change to the existing password.
    
ConfirmPassword
:   Value is identical to ClearPassword.

### Processing
SysUserId is used to identify the user to update. The EmailAddr and UserId are not used as identifiers for update since they may have new values in the update.

If EmailAddr has a new value, this will trigger verification as when creating a new user.

### Response
Same [response as when creating a new user](#Create-User-Response).

## Authentication using a password {#Login}

Most requests need the context of an authenticated user before the request processing is started. The context takes the form of [session cookies](#SessionCookies) in the headers of the request. In order to receive these cookies, this password-based login request is used.

### Request
The HTTP method and URL is: POST /session/login

No authenticated user context is required for this request.

Example:

    {
      "UserIdentifier": "janedoe@example.org",
      "ClearPassword": "big-secret-2000"
    }

UserIdentifier
:   Value identifies the user.

    Value can be one of the values of EmailAddr, UserId or SysUserId associated with the user.

ClearPassword
:   Value is the clear password as provided by the user.

### Processing

See the [processing of session cookies](#Authenticating)

### Response {#LoginResponse}

Example 1:

    Set-Cookie:SessionToken=c30dc1c5-757d-456a-459f-e85431df0e0b; Path=/; Expires=Sun, 06 Apr 2013 23:23:47 UTC; Secure
    Set-Cookie:Salt=a78b876abee86c14360d752843681df16124c17ba1c0fec8a96bd450f592673d; Path=/; Expires=Sun, 06 Apr 2013 23:23:47 UTC; Secure
    Set-Cookie:SysUserId=dd36991e-005b-4720-52b3-31ab204ba444; Path=/; Expires=Sun, 06 Apr 2013 23:23:47 UTC; Secure

    {
      "SessionToken":"c30dc1c5-757d-456a-459f-e85431df0e0b",
      "Salt":"a78b876abee86c14360d752843681df16124c17ba1c0fec8a96bd450f592673d",
      "SessionTTL":300,
      "SysUserId":"dd36991e-005b-4720-52b3-31ab204ba444",
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

Example 2:

    {
      "SessionToken":"",
      "Salt":"",
      "SessionTTL":0,
      "SysUserId":"",
      "UserId":"",
      "EmailAddr":"",
      "EmailVerified":false,
      "FirstName":"",
      "LastName":"",
      "TzName":"",
      "ValidationResult": {
          "Status":"Invalid",
          "Message":"Missing credentials",
          "SystemRef":"Verify",
          "PropInError":"",
          "PropErrorMsg":""
      }
    }

SessionToken
:   Value is a temporary token that is sent in future requests requiring authentication.

Salt
:   Value was used during the encryption of the token on the server. The server does stores the encrypted version of the SessionToken only.

SessionTTL
:   Values is the number of seconds that the SessionToken may be expected to be valid for. This is used as a hint to the client, so that it may refresh the session before it expires. 

SysUserId
:   Value is the UUID of the user that just authenticated

UserId .. TzName
:   These are the attributes of the user record.

ValidationResult
:   See [ValidationResult](#ValidationResult)


## Retrieve user and session details

### Request

The HTTP method and URL is: GET /session/login

The [session cookies](#SessionCookies) as describe below must be sent in the HTTP header.

### Response

The response is the same as the [response](#LoginResponse) to a regular password based login.


## Get a Reset Token

If the user who wishes to login has forgotten the password, the user can provide her email address and a token will be emailed to that address. That [token can be used](#UseResetToken) to login once only.

### Request

The HTTP method and URL is: GET /session/reset/{EmailAddr}

No authenticated user context is required for this request.

### Processing

The following conditions need to be satisfied for a reset token to be emailed to the user:

* EmailAddr must match a simple regular expression for email addresses.
* A user must exist with the given EmailAddr.
* The user must be permitted to login.
* An active reset token must not already exist for the user. This is necessary to limit spamming by malicious reset attempts.

If the above conditions are satisfied a reset token is generated and given a limited time to live. The server keeps an encrypted version of the reset token and emails the clear token to the EmailAddr.

The user's password is left unchanged, as it must.

### Response 

No indication of success or failure is given in the HTTP response. To do so, would leak sensitive information.

Example:

    { "SystemRef": "getResetToken-378242:" }

## Use a Reset Token {#UseResetToken}

Using a reset token, is another way of logging in. The reset token can only be used once. After logging in this way, it is expected that the client will present the user with the opportunity to change her password.

### Request

The HTTP method and URL is: GET /session/reset/{EmailAddr}/token/{Token}

No authenticated user context is required for this request.

### Processing

The following conditions need to be satisfied for the reset token to be used successfully:

* EmailAddr must match a simple regular expression for email addresses.
* The given Token must be parsable.
* A user must exist with the given EmailAddr.
* The user must have an associated encrypted token.
* The user must be permitted to login.
* The associated encrypted token must have not expired.
* The associated encrypted token must match the encrypted version of the given Token.

If the above conditions are satisfied the server's reset token is removed, thus ensuring it can only be used once.

The user's password is left unchanged. It is expected that the client will use the response to generate an update request to change the password.

### Response

The response is the same as the [response](#LoginResponse) to a regular password based login.

## Logout

### Request

The HTTP method and URL is: POST /session/logout

No authenticated user context is required for this request.

Example:

    {
      "SessionToken":"b6c828ab-b726-4a69-7fe4-2be445fc6d42",
      "Salt":"49b01156ede8ac0350d1846b9b7151457bd709e23e5e7002eebb18276b1daf4e"
    }

### Processing

The session is destroyed.

It is expected that the client will remove the now useless [session cookies](#SessionCookies) stored in the browser.

### Response 

No indication of success or failure is given in the HTTP response. To do so, would be meaingless to regular users and leak information to malicious ones.

Example:

    { "SystemRef": "doLogout-229451:" }






# Protocol for HTTP requests
The HTTP method (GET, PUT, POST, DELETE) has meaning.

The routing of the HTTP request to the correct handler depends on the URL and the HTTP method.

## Authentication of Request using a SessionToken {#SessionCookies}

All requests requiring an authenticated user, send an HTTP cookie header containing session info. The session info was originally set in the [authentication response](#LoginResponse) after logging-in using a password or using a reset token.


Example:

    Cookie:SessionToken=ff0096d9-c526-4876-7f43-c137b881693c; Salt=b89380cc14db527f9389141c01466eaba39b086bc471ba0ba234a0d5e209a27b; SysUserId=dd36991e-005b-4720-52b3-31ab204ba444

SessionToken
:   UUID of the session.

Salt
:   The salt used in the encrypted version of the SessionToken held by the server.

SysUserId
:   The user associated with the session.

### Processing {#Authenticating}
The same authentication code is used whether [using a password](#Login) or [session cookies](#SessionCookies). A user identifier is sent in both cases.

The following needs to be satisfied for the user to be authenticated:

* The user identifier must identify an actual user.
* If using a password, the password supplied must match the password on record
* If using session cookies, the session must not have expired and the remote IP Address and UserAgent must also be unchanged.
* The user is allowed to login.
* The user has a verified EmailAddr. If the EmailAddr is not verified then a new verification email is sent. This cannot be used for malicious spamming since the user provided acceptable credentials except for the unverified EmailAddr on record.

Successful authentication with a password creates a new session. In this way a user may have multiple sessions active at a time.

Successful authentication with session cookies, continues an existing session by extending the expiration time. 

## ValidationResult {#ValidationResult}
A JSON fragment used in responses.

Example 1:

    "ValidationResult":
      {
        "Status":"OK",
        "Message":"New user registered successfully",
        "SystemRef":"doUser-069599:",
        "PropInError":"",
        "PropErrorMsg":""
      }

Example 2:

    "ValidationResult":
      {
        "Status":"Invalid",
        "Message":"Data validation failed",
        "SystemRef":"doUser-774264:",
        "PropInError":"EmailAddr",
        "PropErrorMsg":"Not a valid email address"
      }

Status
:   Values "OK" indicates a valid request was processed, "Invalid" indicates some error in the request. The specific error will be found in PropInError and PropErrorMsg.

Message
:   A message targeted at the end user, describing the outcome in general.

SystemRef
:   Useful in debugging. This reference is used to tag log file messages generated during the processing of the specific request that generated the response.

PropInError
:   The name of the property that is in error, or failed validation. When Status is "OK", this will be blank.

PropErrorMsg
:   A message targeted at the end user, describing the error in the property given by PropInError. When Status is "OK", this will be blank.

# Notes

Nginx can be used as a router and load balancer to scale performance horizontally. This means that there can be multiple instances of a service running (e.g. sessiond). This implies that each instance needs its instance specific config and shared config info. It also implies that any caching solution cannot assume a single instance, which is why the caching that was tries was removed.

# Installation

## Postgres Database

* The latest version (9.3.4) was used and tested during development.
* A Postgres expert professional should install, secure and configure the cluster.
* A single role (sessionr) should be given the minimal priveleges needed, and this role should be required to authenticate rigorously at connection time. (See session-pg-schema.sql for the minimal priveleges.)
* Create the database objects as described in session-pg-schema.sql
* Save the database source string needed by the Go driver, something like: "user=sessionr password='big secret' dbname=sessdb host=localhost port=5432 sslmode=disable"
* Configure the sessiond cluster by updating and inserting rows into session.config and session.instconfig

## Nginx (reverse proxy / load balancer)
* The latest version (1.4.7) was used and tested during development.
* An nginx expert professional should install, secure and configure nginx.
* **TODO** more details on the proxy rules, ssl, and load balancing needed.

## sessiond instances
* Instances are started using:

        sessiond -instance="$INSTANCEID" -stderrthreshold=FATAL -log_dir="$LOGDIR" -v=2 &

* $INSTANCEID is used to select the instance specific configuration
* $LOGDIR is where this instance will log to
* The user will need to enter the database source string and the server key on the command line for each instance


[scrypt]: https://code.google.com/p/go/source/browse/?repo=crypto#hg%2Fscrypt 
