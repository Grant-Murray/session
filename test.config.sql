UPDATE session.config SET 
SessionTimeout = 60*5, /* 5 minutes */
SessionMaxLife = 18*60*60, /* 18 hours */
PasswordResetExpiresDuration = 4*60*60, /* 4 hours */
SmtpServerHost = 'test.mailbot.net',
SmtpServerPort = 26,
SmtpFrom = 'no-reply@mailbot.net',
SmtpAuthUsername = 'no-reply@mailbot.net',
SmtpAuthPassword = 'zFbfrrRUNBdxBHaaJCNh8X',

ResetTemplate = 
'To: {{.FirstName}} {{.LastName}}<{{.EmailAddr}}>
From: Plog Admin NO REPLY<no-reply@mailbot.net>
Subject: [ZM Plog] Password Reset

Dear {{.FirstName}},

This email was sent because someone requested a password reset 
using this email address {{.EmailAddr}}

Please load this link in your browser and pick a new password:

https://plog.org:8004/#/reset/{{.EmailAddr}}/token/{{.Token}}

If you did not request a password reset, 
then just delete this email.

Regards, Grant
btw Do not reply to this email address, use my regular one.',

VerifyTemplate = 
'To: {{.FirstName}} {{.LastName}}<{{.EmailAddr}}>
From: Plog Admin NO REPLY<no-reply@mailbot.net>
Subject: [ZM Plog] Email Address Verification

Dear {{.FirstName}},

This email was sent because you registered on the Plog and
I need to verify your email address. Please load this link
in your browser to verify your email address:

https://plog.org:8004/#/verify/{{.EmailAddr}}/token/{{.Token}}

If you did not register on the plog, then just delete this email.

Regards, Grant
btw Do not reply to this email address, use my regular one.',

HttpsHost = 'plog.org', /* needs to be in /etc/hosts */
HttpsPort = '10443',
HttpsKey = '-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDV6C4tnQLfrolm
azcdSiGCWGiwtVc+gIoT6gsFPIK+oFdLMHUIFAGhoqMiP5TRHiIJGsW8aUwGpP62
+OBNtHlhbOgzxPavqDr3b4kAF9hCXQt1lT8NnFOmmpGk1vueqsZSsZkJdCUg1CnV
PiRhw+82cyrCSjkrwtY+/f4/6Itlpcj0U5E6TI1pwHSCi3TC2FGaZyDfmWUHgmTE
HlEoTs1oVMGtb4htOHnu7zRHAtmii2JxnyWND0jglPnpMTbFDCvobuGwgwuP34BM
tWqPLGLv/Ff940hmG5pAUV/akbcZj8IFqfN7EgMGItbbvTXUH/jOe5v6OX8yQXK3
ficZ+EZPAgMBAAECggEAWmW0njIsdLsd9dp5gDdD0gHqvELmi9NmhuPxpFTeLBE2
0t+3laJeziAdMOwNyBIj8BUQW39kUaqIumqS4EPUyAduWfJzDejagpbwHsn06pbH
sPlRnD7kWxQXWMJBs9wX0/qZ4hTjW+xNgYCxf19+SFSDTXhwkL3WLOjJ+dgckOeo
6DCFF3nVv3w9CjIe6e+uOdHFJsBELTCeT+FHVV3cHvxX14liOrHixiqLmpBuOw3v
LiTPeUNbCqOWB1TBbNG08A8wQfBqXKtp5K1nxjcYRsZIIDTtm6bVsxGRWpre+XR2
TiaqCtApzwvqbmET582nkOwnYxTQ3H+dFZfsJZrSgQKBgQD2YcCF4HGBiUtYndPD
zO6M0XGwP6KRnLTnNCjxanUfbAVD3bo3tXNS4Tbiek4fO+rxsco3VuybNLvSteyT
vyZ/ly9erzt5V/Oserhop6DEuy3wCXKvyMrOMR2peoZ+U5Cl28ElbiPLC64xOAdm
aLb04WzlX4cznG0+ReLEsIAfbQKBgQDeQeLuSlZD/UclmEP0uzaYxgA+2sZdRoZl
c5EvUddyj/nMmgMp7r9ofrvaQZOqxCEowzJFohHtSHpZPAq694XSwLhWCRyRp2C/
tMlHO2kGfUlQYVCr+6EW8uM39qHVpW28KHVftbpp+RJcCtT+g8xBnCBiKlWH6a3P
+jZbx5ybKwKBgHQGCHGDBjCoBNFQUX7tLJEnuE/1R4smrpIKIBW/ujP33GrfKWg+
jHZFFGGGku9mefcjcESrLHTSWniZrzTMWUbQXUBLaMh1wIxCpkCyX6UFOFbHPDjH
Z6m9u2gqCNfIZl+UotoLidN+RqNq7SEuwqmC1pMVb0fArDkdE/Ln4w3pAoGBAL57
CykcTpiQbjRbLgqFlIIUV8uGpjD0q2QxSoGai6IkoHrol8ONWUAONaMVRqA43Q5Z
VDF3eBO7ZRgrLCsWzftUrecWggSWxYUnRMWmthkYsQeRj5kF3AaV/YRN/F7lG4oB
xq5TSkNecoytv+OtQxYL33kiPRFxhURUddfs2FvnAoGAVXDl8rdv73xhj202ROjh
zfNGzlNCASv6tTbrtCqMva9tc1lSBkMNP6SpK1O6Sm1hXNzOu1urI4HPR8Du3218
mlIl4ymFTzIf4xU/u2MLFgt/6pTOKB6mM2sWVhVeOiaSguZYuamuNskvu41eJWVS
eyqrEtky5MIoSpwchlIwVuw=
-----END PRIVATE KEY-----',
  HttpsCert = '-----BEGIN CERTIFICATE-----
MIIDTzCCArigAwIBAgIBAjANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKQ2FsaWZvcm5pYTERMA8GA1UECgwIR0xNIFRlc3QxDzANBgNVBAMM
BkdMTSBDQTEkMCIGCSqGSIb3DQEJARYVZW1haWxAZ3JhbnRtdXJyYXkuY29tMB4X
DTEzMDkyODE5MTYwM1oXDTE0MDkyODE5MTYwM1owbjELMAkGA1UEBhMCVVMxEzAR
BgNVBAgMCkNhbGlmb3JuaWExETAPBgNVBAoMCEdMTSBUZXN0MREwDwYDVQQDDAhw
bG9nLm9yZzEkMCIGCSqGSIb3DQEJARYVZW1haWxAZ3JhbnRtdXJyYXkuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1eguLZ0C366JZms3HUohglho
sLVXPoCKE+oLBTyCvqBXSzB1CBQBoaKjIj+U0R4iCRrFvGlMBqT+tvjgTbR5YWzo
M8T2r6g692+JABfYQl0LdZU/DZxTppqRpNb7nqrGUrGZCXQlINQp1T4kYcPvNnMq
wko5K8LWPv3+P+iLZaXI9FOROkyNacB0got0wthRmmcg35llB4JkxB5RKE7NaFTB
rW+IbTh57u80RwLZooticZ8ljQ9I4JT56TE2xQwr6G7hsIMLj9+ATLVqjyxi7/xX
/eNIZhuaQFFf2pG3GY/CBanzexIDBiLW27011B/4znub+jl/MkFyt34nGfhGTwID
AQABo3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVy
YXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUTu/ykZytBklUe+r05a0/IWi1Jrow
HwYDVR0jBBgwFoAU6K3nBZy2XLJIZMBk0iDJhu7vnTkwDQYJKoZIhvcNAQEFBQAD
gYEARUhKn0LO2cruizriNGiCKpISs8plY3V1ZEkOAqA6aM9X8dH5ibPanQEeXWCl
ZzY6IFE0QZD4VPgXe4omTNu5wWmehhQuR+my4uefe1NcpdsxoqPGTZFhyxcoiM4p
JRLwW7yf6ZZEBOb83X25Y7ih2pL6dZ58x9+ElSLKDrET/RM=
-----END CERTIFICATE-----'
;
