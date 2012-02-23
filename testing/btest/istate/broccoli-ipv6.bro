# @TEST-REQUIRES: test -e $BUILD/aux/broccoli/src/libbroccoli.so || test -e $BUILD/aux/broccoli/src/libbroccoli.dylib
#
# @TEST-EXEC: btest-bg-run bro bro %INPUT $DIST/aux/broccoli/test/broccoli-v6addrs.bro
# @TEST-EXEC: btest-bg-run broccoli $BUILD/aux/broccoli/test/broccoli-v6addrs
# @TEST-EXEC: btest-bg-wait -k 20
# @TEST-EXEC: btest-diff bro/.stdout
# @TEST-EXEC: btest-diff broccoli/.stdout

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}

