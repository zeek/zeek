# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -b -m -r $TRACES/http/connect-with-smtp.trace %INPUT
# @TEST-EXEC: btest-bg-wait 60

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/smtp
@load base/protocols/tunnels
@load base/frameworks/dpd
