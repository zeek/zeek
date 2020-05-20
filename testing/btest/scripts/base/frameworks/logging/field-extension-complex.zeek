# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn

type InnerRecord: record {
	a: count;
	b: count;
	c: count;
};

type InnerLoggedRecord: record {
	a: count &log;
	b: count;
	c: count &log;
	d: set[count] &log;
};

type Extension: record {
	write_ts: time &log;
	stream: string &log;
	inner: InnerRecord;
	innerLogged: InnerLoggedRecord &log;
	system_name: string &log;
};

function add_extension(path: string): Extension
	{
	return Extension($write_ts    = network_time(),
	                 $stream      = path,
	                 $system_name = peer_description,
	                 $inner = InnerRecord($a=1,$b=2,$c=3),
	                 $innerLogged = InnerLoggedRecord($a=1,$b=2,$c=3,$d=set(1,2,3,4))
	                 );
	}

redef Log::default_ext_func = add_extension;
