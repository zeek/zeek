# @TEST-SERIALIZE: comm
#
# @TEST-REQUIRES: test -e $BUILD/aux/broccoli/src/libbroccoli.so || test -e $BUILD/aux/broccoli/src/libbroccoli.dylib
# @TEST-REQUIRES: ifconfig | grep -q -E "inet6 ::1|inet6 addr: ::1"
#
# @TEST-EXEC: btest-bg-run bro bro $DIST/aux/broccoli/test/broccoli-v6addrs.bro "Communication::listen_ipv6=T"
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run broccoli $BUILD/aux/broccoli/test/broccoli-v6addrs -6 ::1
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff bro/.stdout
# @TEST-EXEC: btest-diff broccoli/.stdout
