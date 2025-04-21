# Tests processing of half-duplex client-side connections, including no
# analyzer_failed.log output.

# @TEST-EXEC: zeek -r $TRACES/ssh/ssh.client-side-half-duplex.pcap %INPUT
# @TEST-EXEC: btest-diff analyzer_debug.log
# @TEST-EXEC: btest-diff ssh.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff .stdout

@load frameworks/analyzer/analyzer-debug-log.zeek

