# @TEST-EXEC: zeek -b -C -r $TRACES/vntag.pcap %INPUT
# @TEST-EXEC: btest-diff unknown_protocols.log

@load policy/misc/unknown-protocols
