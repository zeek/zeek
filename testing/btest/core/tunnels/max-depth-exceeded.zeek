# @TEST-DOC: Set a too small Tunnel::max_depth value, observe the effects.
#
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/vxlan-triple-v2.pcap %INPUT
# @TEST-EXEC: zeek-cut -m uid id.orig_h id.resp_p id.resp_h id.resp_p proto history service tunnel_parents < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff tunnel.log
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: test ! -f dns.log
#
@load base/frameworks/notice/weird
@load base/frameworks/tunnels
@load base/protocols/conn
@load base/protocols/dns

redef Tunnel::max_depth = 2;
