# @TEST-DOC: Tests that a DNS dynamic update packet doesn't error but reports an unknown opcode weird
# @TEST-EXEC: zeek -b -C -r $TRACES/dns/dynamic-update.pcap %INPUT
# @TEST-EXEC: btest-diff weird.log

@load base/frameworks/notice/weird
@load base/protocols/dns
