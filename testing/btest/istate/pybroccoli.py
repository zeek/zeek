# @TEST-SERIALIZE: comm
#
# @TEST-REQUIRES: test -e $BUILD/aux/broccoli/src/libbroccoli.so || test -e $BUILD/aux/broccoli/src/libbroccoli.dylib
# @TEST-REQUIRES: test -e $BUILD/aux/broccoli/bindings/broccoli-python/_broccoli_intern.so
#
# @TEST-EXEC: btest-bg-run bro    bro %INPUT $DIST/aux/broccoli/bindings/broccoli-python/tests/test.bro
# @TEST-EXEC: btest-bg-run python PYTHONPATH=$DIST/aux/broccoli/bindings/broccoli-python/:$BUILD/aux/broccoli/bindings/broccoli-python python $DIST/aux/broccoli/bindings/broccoli-python/tests/test.py
# @TEST-EXEC: btest-bg-wait -k 20
# @TEST-EXEC: btest-diff bro/.stdout
#
# @TEST-EXEC: sed 's/instance at [^>]*>/instance at >/' <python/.stdout >python/.stdout.filtered
# @TEST-EXEC: btest-diff python/.stdout.filtered

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}


