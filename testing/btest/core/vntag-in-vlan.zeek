# @TEST-EXEC: zeek -b -C -r $TRACES/vntag_vlan_sandwich_clean.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn
