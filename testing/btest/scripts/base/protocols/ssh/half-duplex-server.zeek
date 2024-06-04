# Tests processing of half-duplex server-side connections, including no
# analyzer.log output.

# @TEST-EXEC: zeek -r $TRACES/ssh/ssh.server-side-half-duplex.pcap %INPUT
# @TEST-EXEC: test ! -e analyzer.log
# @TEST-EXEC: btest-diff ssh.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff .stdout
