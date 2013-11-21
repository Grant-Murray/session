#!/bin/bash

TYP='test'
#TYP='bench'

# ensure a clean slate
sudo rm -f /tmp/mailbot.boxes/*
sudo rm -f /tmp/sessdb.*

# install 
go clean
go install || exit

# start sessiond
../sessiond/run.bash

# verify sessiond is running
if [ "$(pidof sessiond)" = "" ]; then
  echo sessiond did not start
  exit 1
fi

if [ "$TYP" = "test" ]; then
  go test -v
else
  go test -v -run='Setup' -bench=. # -cpuprofile='/tmp/session_cpuprofile'
fi

PSQL="psql --username=postgres --dbname=sessdb"
echo "select * from session.log"     | $PSQL > /tmp/sessdb.session.log
echo 'select * from session.user'    | $PSQL --expanded > /tmp/sessdb.session.user
echo 'select * from session.session' | $PSQL --expanded > /tmp/sessdb.session.session

# clean up
killall sessiond
$PSQL -c 'DROP SCHEMA IF EXISTS session CASCADE;'
