# @TEST-DOC: Tests the output from the multicast-participants policy script

# @TEST-EXEC: zeek -C -r $TRACES/igmp/home-multicast-short.pcap %INPUT
# @TEST-EXEC: btest-diff multicast_participants.log

@load policy/protocols/conn/multicast-participants
