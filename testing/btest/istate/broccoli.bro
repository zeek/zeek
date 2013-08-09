# @TEST-SERIALIZE: comm
#
# @TEST-REQUIRES: test -e $BUILD/aux/broccoli/src/libbroccoli.so || test -e $BUILD/aux/broccoli/src/libbroccoli.dylib
#
# @TEST-EXEC: btest-bg-run bro bro %INPUT $DIST/aux/broccoli/test/broping-record.bro
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run broccoli $BUILD/aux/broccoli/test/broping -r -c 3 127.0.0.1
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: cat bro/ping.log | sed 's/one-way.*//g' >bro.log
# @TEST-EXEC: cat broccoli/.stdout | sed 's/time=.*//g' >broccoli.log
# @TEST-EXEC: btest-diff bro.log
# @TEST-EXEC: btest-diff broccoli.log

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}

