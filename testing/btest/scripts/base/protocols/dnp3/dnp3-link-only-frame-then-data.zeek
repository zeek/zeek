# @TEST-DOC: A link-layer-only DNP3 frame (LENGTH 5, e.g. REQUEST_LINK_STATUS) must not swallow the frames that follow it.
#
# @TEST-EXEC: zeek -b -r $TRACES/dnp3/dnp3-link-only-frame-then-data.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m dnp3.log
# @TEST-EXEC: test ! -e weird.log
# @TEST-EXEC: test ! -e analyzer.log

@load base/protocols/conn
@load base/protocols/dnp3
@load base/frameworks/notice/weird
@load base/frameworks/analyzer/logging
