# @TEST-EXEC: zeek -b -r $TRACES/auth_change_session_keys.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

# The other tests of Log::default_field_name_map used to not catch an invalid
# memory free for some reason, but this test did reproduce a crash
# consistently (now fixed).

@load base/protocols/conn

redef Log::default_field_name_map = {
	["id.orig_h"] = "src_ip",
	["id.orig_p"] = "src_port",
	["id.resp_h"] = "dst_ip",
	["id.resp_p"] = "dst_port"
};
