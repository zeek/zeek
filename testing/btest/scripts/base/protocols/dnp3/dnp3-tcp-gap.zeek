# @TEST-DOC: A TCP gap in a DNP3 connection loses only the data around it: the analyzer resynchronizes after the gap instead of stopping.
#
# @TEST-EXEC: zeek -b -r $TRACES/dnp3/dnp3-tcp-gap.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m dnp3.log
# @TEST-EXEC: btest-diff-cut -m uid name weird.log
# @TEST-EXEC: test ! -e analyzer.log

@load base/protocols/dnp3
@load base/frameworks/notice/weird
@load base/frameworks/analyzer/logging
