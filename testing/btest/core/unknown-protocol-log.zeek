# @TEST-EXEC: zeek -b -r $TRACES/lldp.pcap %INPUT
# @TEST-EXEC: btest-diff unknown_protocols.log

@load misc/unknown-protocols

redef record UnknownProtocol::Info$protocol_id_num += { &log };
