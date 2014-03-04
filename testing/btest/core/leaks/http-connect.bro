# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: bro  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run bro bro -b -m -r $TRACES/http/connect-with-smtp.trace %INPUT
# @TEST-EXEC: btest-bg-wait 15

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/smtp
@load base/protocols/tunnels
@load base/frameworks/dpd
