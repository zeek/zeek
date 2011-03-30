# @TEST-REQUIRES: grep -vq '#define BROv6' $BUILD/config.h
# @TEST-REQUIRES: test -e $BUILD/aux/broccoli/src/libbroccoli.so
# @TEST-REQUIRES: test -e $BUILD/aux/broccoli/bindings/broccoli-python/_broccoli_intern.so
#
# @TEST-EXEC: btest-bg-run bro bro $DIST/aux/broccoli/bindings/broccoli-python/tests/test.bro
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run python python $DIST/aux/broccoli/bindings/broccoli-python/tests/test.py
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff bro/.stdout.log
# @TEST-EXEC: btest-diff broccoli/.stdout.log


