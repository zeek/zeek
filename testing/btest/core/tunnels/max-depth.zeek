# @TEST-DOC: A DNS request encapsulated in 3 layers of VXLAN. Funky but not all that unusual.
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/vxlan-triple-v2.pcap %INPUT
# @TEST-EXEC: zeek-cut -m uid id.orig_h id.resp_p id.resp_h id.resp_p proto history service tunnel_parents < conn.log > conn.log.cut
# @TEST-EXEC: zeek-cut -m uid id.orig_h id.resp_p id.resp_h id.resp_p query < dns.log > dns.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff tunnel.log
# @TEST-EXEC: btest-diff dns.log.cut
#
@load base/frameworks/tunnels
@load base/protocols/conn
@load base/protocols/dns
