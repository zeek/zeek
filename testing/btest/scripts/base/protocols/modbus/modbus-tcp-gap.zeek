# @TEST-DOC: A TCP gap in a Modbus/TCP connection loses only the request it cuts: the analyzer resumes at the next MBAP header instead of reading later requests out of alignment.
#
# @TEST-EXEC: zeek -b -r $TRACES/modbus/modbus-tcp-gap.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m modbus.log
# @TEST-EXEC: btest-diff-cut -m uid name weird.log
# @TEST-EXEC: test ! -e analyzer.log

@load base/protocols/modbus
@load base/frameworks/notice/weird
@load base/frameworks/analyzer/logging
