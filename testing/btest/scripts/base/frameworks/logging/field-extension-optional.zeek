# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn

type Extension: record {
	write_ts: time &log;
	stream: string;
	system_name: string &log &optional;
	undefined_string: string &log &optional;
};

function add_extension(path: string): Extension
	{
	return Extension($write_ts    = network_time(),
	                 $stream      = path,
	                 $system_name = peer_description);
	}

redef Log::default_ext_func = add_extension;
