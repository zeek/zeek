# @TEST-DOC: Tests a GRE ARUBA trace that contains IEEE 802.11 CCMP headers. This should report a weird about encrypted data.
# @TEST-EXEC: zeek -C -b -r $TRACES/tunnels/gre-aruba-ccmp.pcap %INPUT

@load base/frameworks/notice/weird
