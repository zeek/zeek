# @TEST-SERIALIZE: comm
#
# @TEST-REQUIRES: test -e $BUILD/aux/broccoli/src/libbroccoli.so || test -e $BUILD/aux/broccoli/src/libbroccoli.dylib
# @TEST-REQUIRES: test -e $BUILD/aux/broccoli/bindings/broccoli-python/_broccoli_intern.so
#
# @TEST-EXEC: btest-bg-run bro    bro %INPUT $DIST/aux/broccoli/bindings/broccoli-python/tests/test.bro
# @TEST-EXEC: sleep 2
# @TEST-EXEC: btest-bg-run python PYTHONPATH=$DIST/aux/broccoli/bindings/broccoli-python/:$BUILD/aux/broccoli/bindings/broccoli-python python $DIST/aux/broccoli/bindings/broccoli-python/tests/test.py
# @TEST-EXEC: btest-bg-wait -k 20
# @TEST-EXEC: btest-diff bro/.stdout
#
# @TEST-EXEC: sed -e 's/instance at [^>]*>/instance at >/' -e 's/object at [^>]*>/instance at >/' <python/.stdout >python/.stdout.filtered
# @TEST-EXEC: TEST_DIFF_CANONIFIER="sed -e 's/^\([-]*[0-9][0-9]*\)L/\1/' | $SCRIPTS/diff-remove-timestamps" btest-diff python/.stdout.filtered

event remote_connection_closed(p: event_peer)
	{
	terminate();
	}


