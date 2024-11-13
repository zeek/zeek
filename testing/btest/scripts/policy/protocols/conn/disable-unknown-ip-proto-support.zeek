# @TEST-DOC: Test the policy for removing the unknown IP protocol field and connections from conn.log
# @TEST-EXEC: zeek -r $TRACES/cisco-fabric-path.pcap %INPUT
# @TEST-EXEC: test $(head -1 conn.log | jq 'has("ip_proto")') = "false"
# @TEST-EXEC-FAIL: cat conn.log | jq .proto | sort | uniq | grep unknown_transport

@load policy/protocols/conn/disable-unknown-ip-proto-support

redef LogAscii::use_json = T;
