# @TEST-REQUIRES: grep -vq '#define BROv6' $BUILD/config.h
# @TEST-REQUIRES: test -e $BUILD/aux/broccoli/src/libbroccoli.so
#
# @TEST-EXEC: btest-bg-run bro bro $DIST/aux/broccoli/test/broping-record.bro
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run broccoli $BUILD/aux/broccoli/test/broping -r -c 5 127.0.0.1
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff bro/.stdout.log
# @TEST-EXEC: btest-diff broccoli/.stdout.log


