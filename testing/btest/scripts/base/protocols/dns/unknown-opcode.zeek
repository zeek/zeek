# @TEST-DOC: An unsupported DNS opcode produces a weird but no X history marker.
#
# @TEST-EXEC: zeek -b -r $TRACES/dns/unknown-opcode.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log
# @TEST-EXEC: btest-diff-cut -m dns.log

@load base/protocols/conn
@load base/protocols/dns
@load base/frameworks/notice/weird
