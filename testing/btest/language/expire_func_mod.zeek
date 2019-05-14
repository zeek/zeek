# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

module Test;

redef exit_only_after_terminate = T;
redef table_expire_interval = .1 secs ;

export {
	global table_expire_func: function(t: table[string] of count,
	                                   s: string): interval;

	global t: table[string] of count
		&write_expire=0 secs
		&expire_func=table_expire_func;
}

event die()
	{
	terminate();
	}

function table_expire_func(t: table[string] of count, s: string): interval
	{
	t[s] += 1 ;

	print fmt("inside table_expire_func: %s, %s", s, t[s]);

	if ( t[s] < 10 )
		return .1 secs ;

	schedule .1sec { die() };
	return 0 secs;
	}

event zeek_init()
	{
	local s="ashish";
	t[s] = 1 ;
	print fmt("starting: %s, %s", s, t[s]);
	}
