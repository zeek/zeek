# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn

redef Log::default_field_name_map = {
	["id.orig_h"] = "src",
	["id.orig_p"] = "src_port",
	["id.resp_h"] = "dst",
	["id.resp_p"] = "dst_port",
};