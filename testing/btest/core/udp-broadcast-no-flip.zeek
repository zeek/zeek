# @TEST-DOC: Pcap contains broadcast with port 40190 to port 7437. Set likely_server_ports to 40190 but don't expect this connection to be flipped.

# @TEST-EXEC: zeek -b -r $TRACES/udp-broadcast.pcap %INPUT
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p history < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut

@load base/protocols/conn

redef likely_server_ports += { 40190/udp };
