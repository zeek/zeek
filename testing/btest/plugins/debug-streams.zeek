# This requires Zeek with debug streams support.
# @TEST-REQUIRES: test "$($BUILD/zeek-config --build_type)" = "debug"

# @TEST-EXEC: zeek -B plugin-Zeek-HTTP -e 'event zeek_init() { print "zeek_init"; }' 2>zeek.stderr

# Variations on case that should all work:
# @TEST-EXEC: zeek -B PLUGIN-zeek-http -e 'event zeek_init() { print "zeek_init"; }' 2>zeek.stderr
# @TEST-EXEC: zeek -B plugin-zeek-TCP_PKT -e 'event zeek_init() { print "zeek_init"; }' 2>zeek.stderr
# @TEST-EXEC: zeek -B plugin-zeek-tcp-pkt -e 'event zeek_init() { print "zeek_init"; }' 2>zeek.stderr

# A plugin that really does not exist:
# @TEST-EXEC-FAIL: zeek -B plugin-notaplugin -e 'event zeek_init() { print "zeek_init"; }' 2>zeek.stderr

# @TEST-EXEC: btest-diff zeek.stderr
