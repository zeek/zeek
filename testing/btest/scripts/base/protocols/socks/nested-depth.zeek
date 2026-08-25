# @TEST-DOC: Verify nested SOCKS analysis stops at the tunnel depth limit.
#
# @TEST-EXEC: zeek -b -C -r $TRACES/socks-nested-depth.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log

@load base/frameworks/notice/weird
@load base/protocols/conn
@load base/protocols/socks

redef Tunnel::max_depth=2;
