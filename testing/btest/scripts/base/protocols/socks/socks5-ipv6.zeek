# @TEST-DOC: Verify SOCKS5 IPv6 request and bound address logging (#5854).
#
# @TEST-EXEC: zeek -b -r $TRACES/socks/socks5-ipv6.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m request.host bound.host socks.log

@load base/protocols/socks
