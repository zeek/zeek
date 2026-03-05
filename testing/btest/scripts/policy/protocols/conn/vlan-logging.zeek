# A basic test of the vlan logging script

# @TEST-EXEC: zeek -b -r $TRACES/q-in-q.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load protocols/conn/vlan-logging
