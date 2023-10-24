# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff .stderr

@load base/protocols/conn

type Extension: record {
	write_ts: time &log;
	stream: string &log;
	system_name: string &log;
};

function add_extension(path: string): Extension
	{
	}

redef Log::default_ext_func = add_extension;
