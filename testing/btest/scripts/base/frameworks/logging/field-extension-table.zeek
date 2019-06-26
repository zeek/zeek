# @TEST-EXEC-FAIL: zeek -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load base/protocols/conn

type Extension: record {
	write_ts: time &log;
	stream: string &log;
	tab: table[count] of count &log;
	system_name: string &log;
};

function add_extension(path: string): Extension
	{
	return Extension($write_ts    = network_time(),
	                 $stream      = path,
	                 $system_name = peer_description,
	                 $tab         = { [1] = 2, [2] = 3}
	                 );
	}

redef Log::default_ext_func = add_extension;
