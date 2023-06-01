# @TEST-DOC: Tests a GRE ARUBA trace that contains IEEE 802.11 QoS A-MSDU headers. This is testing that the tunnel is detected and that the conn byte size contains both A-MSDU subframe packets.
# @TEST-EXEC: zeek -C -b -r $TRACES/tunnels/gre-aruba-amsdu.pcap %INPUT
# @TEST-EXEC: btest-diff tunnel.log
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn
@load base/frameworks/tunnels
