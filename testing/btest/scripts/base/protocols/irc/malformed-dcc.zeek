# @TeST-DOC: Tests that malformed DCC host/port fields report weirds.
#
# @TEST-EXEC: zeek -b -r $TRACES/irc-dcc-send-malformed-host.pcap %INPUT
# @TEST-EXEC: cat weird.log >> combined.weird.log
# @TEST-EXEC: zeek -b -r $TRACES/irc-dcc-send-malformed-port.pcap %INPUT
# @TEST-EXEC: cat weird.log >> combined.weird.log
# @TEST-EXEC: btest-diff-cut -m combined.weird.log

@load base/protocols/irc
@load base/frameworks/notice/weird
