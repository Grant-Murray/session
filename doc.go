// Copyright 2013 Grant Murray

/*
Package session provides http handlers for managing users and permitting them to start a session by logging in. It is HTTPS based using JSON objects that are stored in a PostgreSQL database.
This package assumes that the caller has called logdb.Initialize to initialize the loggers




Refactoring TODO
    Make sure all SQL is done in the model (verifyemail for example)
    fetchLogs should be moved into package logdb

Next steps TODO
    A doUser test to verify that the cache is correct after profile change

Must have features
    password reset - request which sends an email with token, limit to 1 per day
    password reset - use token to set new password
    domain[3]

Other features
    session_client[1]
    super_user[2]

Nice to have features
    config option that permits only 1 active session per user
    config option that permits login with unverified email address

[1] session_client
    * cached and remote version of VerifyIdentity
    * genericLogin would need to be a HTTPS request
    * vDirty would need to be passed back to remote client (to notify of profile changes)
    * logouts would also need to be sent back

[2] super_user
    * a user who can add/change/deactivate other users in the super_user's domain[3] (requires an Authorization mechanism)
    * would need a way to create the first super_user
    * add users which represent other services (could they sign-up themselves?)
    * should be able to add without verifying email address
    * ability to set login_allowed to false (perhaps instead of deleting)

[3] domain
    * when used in a multi-tenant hosting environment the set of users for one domain needs to be kept separate
    * after logging in the user row can tell which domain the user is in

Convert data:
sed -f ~/plog2013/conversion-script.sed /ZM/bluehost-backup/mysql-backups/mydump-for-postgres.sql > /tmp/mydump-for-postgres.FIXED.sql

*/
package session
