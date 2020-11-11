# This tests the intersection of log filters with a custom extension
# function that also use $include/$exclude: the extension function
# overrides those restrictions.
#
# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff conn-inc.log
# @TEST-EXEC: btest-diff conn-exc.log

@load base/protocols/conn

type Extension: record {
	write_ts: time &log;
	stream: string &log;
	system_name: string &log;
};

function add_extension(path: string): Extension
	{
	return Extension($write_ts    = network_time(),
	                 $stream      = path,
	                 $system_name = peer_description);
	}

redef Log::default_ext_func = add_extension;

event zeek_init()
{
        Log::remove_default_filter(Conn::LOG);
        Log::add_filter(Conn::LOG, [$name="default-inc", $path="conn-inc", $include=set("ts", "uid", "id.orig_h", "id.resp_h")]);
        Log::add_filter(Conn::LOG, [$name="default-exc", $path="conn-exc", $exclude=set("_write_ts")]);
}
