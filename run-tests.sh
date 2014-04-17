#!/bin/bash
# for TEST only, insecure script

TYP='test'
#TYP='bench'

# ensure a clean slate
sudo rm -f /tmp/mailbot.boxes/*
sudo rm -f /tmp/sessdb.*
sudo rm -f /tmp/session.test*

# install 
go clean
go install || exit

# start sessiond
rm "/tmp/session_test.config.bootstrap.input"
../sessiond/run.bash

# verify sessiond is running
if [ "$(pidof sessiond)" = "" ]; then
  echo sessiond did not start
  exit 1
fi

# SERVERKEY must match that used to start sessiond
DBSOURCE="user=postgres password='with spaces' dbname=sessdb host=localhost port=5432 sslmode=disable"
SERVERKEY=fa1725ba8034485170912d8c29d4ef118f3fddd43e21437f0ee167835921b786d4bc6f52027fb858e6a138d6dfa1875d4ec12488464af3dbe79984bc23ffdece
echo -e "$DBSOURCE\n$SERVERKEY" > "/tmp/session_test.config.bootstrap.input"

if [ "$TYP" = "test" ]; then
  go test -v
else
  go test -v -run='Setup' -bench=. # -cpuprofile='/tmp/session_cpuprofile'
fi

PSQL="psql --username=postgres --dbname=sessdb"
echo 'select * from session.user'    | $PSQL --expanded > /tmp/sessdb.session.user
echo 'select * from session.session' | $PSQL --expanded > /tmp/sessdb.session.session
echo 'select * from session.config' | $PSQL --expanded > /tmp/sessdb.session.config
echo 'select * from session.instconfig' | $PSQL --expanded > /tmp/sessdb.session.instconfig

# clean up
killall sessiond
$PSQL -c 'DROP SCHEMA IF EXISTS session CASCADE;'
rm "/tmp/session_test.config.bootstrap.input"
