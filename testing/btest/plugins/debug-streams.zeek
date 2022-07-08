# This requires Zeek with debug streams support.
# @TEST-REQUIRES: test "$($BUILD/zeek-config --build_type)" = "debug"

# @TEST-EXEC: zeek -B plugin-Zeek-HTTP -e 'event zeek_init() { print "zeek_init"; }' 2>zeek.stderr
# @TEST-EXEC-FAIL: zeek -B plugin-zeek-http -e 'event zeek_init() { print "zeek_init"; }' 2>zeek.stderr

# @TEST-EXEC: btest-diff zeek.stderr
