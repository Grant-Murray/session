// Copyright 2013 Grant Murray

/*
Package session provides http handlers for managing users and permitting them to start a session by logging in. It is HTTPS based using JSON objects that are stored in a PostgreSQL database.

Next steps TODO
    Change table to have: EmailAddr and UnverifiedEmailAddr
    UI test when nginx is up, but sessiond is down
    Should each service have its own postgres role? Instead of using postgres as the role. This role should have a minimal set of privileges.

Must have features
    domain[3]

Other features
    session_client[1]
    super_user[2]

Nice to have features
    config option that permits only 1 active session per user
    config option that permits login with unverified email address

[1] session_client
    * finds the load balancer for sessiond backends
    * sends GET /session/login with session cookies
    * avoid temptation to cache anything

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
