# @TEST-DOC: Tests the ip-proto-name-logging policy file
# @TEST-EXEC: zeek -r $TRACES/cisco-fabric-path.pcap %INPUT > out

# @TEST-EXEC-FAIL: cat conn.log | jq 'has("ip_proto_name")' | grep "false"
# @TEST-EXEC: cat conn.log | jq .ip_proto_name | sort | uniq | grep private-encryption
# @TEST-EXEC: btest-diff out

@load policy/protocols/conn/ip-proto-name-logging

redef LogAscii::use_json = T;

event zeek_init() {
	# Test printing out an unknown value from the protocol_names table
	print IP::protocol_names[500];
}
