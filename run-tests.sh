#!/bin/bash

PGDATA=/tmp/sessdb.postgresql
PGPORT=41230
SQLF1=$PGDATA/session-db.sql
TYP='test'
#TYP='bench'

function run_as_pg() {
  CMD=$1
  sudo su -c "$CMD" - postgres
}

if [ -d "$PGDATA" ]
then
  echo "$PGDATA exists already, aborting"
  exit 1
fi

# ensure a clean slate
rm -f /tmp/mailbot.boxes/*
rm -f /tmp/sessdb.*
killall --quiet sessiond

#?? sudo systemctl restart nginx

# install all
go clean
go install || exit
cd ../sessiond
go clean
go install || exit
cd ../session

# create a new temporary database instance
run_as_pg "initdb --auth=trust --pgdata=\"$PGDATA\" --username=postgres"

# start a server running on this instance
run_as_pg "postgres -D \"$PGDATA\" -F -p $PGPORT &"
echo -e "\n\nDatabase in directory $PGDATA should be accessible on port $PGPORT"

# give postgresql some time to start
sleep 3

# create the testing database
run_as_pg "psql -p $PGPORT -U postgres -c \"create database sessdb;\""

# run the session-pg-schema.sql
FULLSQL=/tmp/session.$(date +%s)
cat session-pg-schema.sql test.config.sql > $FULLSQL
sudo mv $FULLSQL $SQLF1
sudo chown postgres $SQLF1
sudo chmod 600 $SQLF1
run_as_pg "psql -p $PGPORT -U postgres -f $SQLF1 sessdb"
sudo rm $SQLF1

sessiond &

if [ "$TYP" = "test" ]; then
  go test -v
else
  go test -v -run='Setup' -bench=. # -cpuprofile='/tmp/session_cpuprofile'
fi

echo "select * from session.log"     | psql -p $PGPORT -U postgres sessdb > /tmp/sessdb.session.log
echo 'select * from session.user'    | psql -p $PGPORT -U postgres --expanded sessdb > /tmp/sessdb.session.user
echo 'select * from session.session' | psql -p $PGPORT -U postgres --expanded sessdb > /tmp/sessdb.session.session

# clean up
killall sessiond
exit
sudo kill $(sudo head -n1 "$PGDATA"/postmaster.pid)
sudo rm -rf "$PGDATA"

