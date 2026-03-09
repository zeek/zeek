# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff out2

module Test;

redef exit_only_after_terminate = T;
redef table_expire_interval = .1 secs ;

global out2 = open("out2");

export {
	global table_expire_func: function(t: table[string] of count,
		s: string): interval;
	global table_expire_func2: function(t: table[string, string, string] of count,
		s: string, s2: string, s3: string): interval;

	global t: table[string] of count
		&write_expire=0 secs
		&expire_func=table_expire_func;

	global tt: table[string, string, string] of count
		&write_expire=0 secs
		&expire_func=table_expire_func2;
}

global die_count = 0;

event die()
	{
	if (die_count < 1)
		{
		++die_count;
		return;
		}
	terminate();
	}

function table_expire_func(t: table[string] of count, s: string): interval
	{
	t[s] = t[s] +  1 ;

	print fmt("inside table_expire_func: %s, %s", s, t[s]);

	if ( t[s] < 10 )
		return .1 secs ;

	schedule .1sec { die() };
	return 0 secs;
	}

function table_expire_func2 (tt: table[string, string, string] of count, s: string, s2: string, s3: string): interval
	{
	tt[s, s2, s3] += 1;

	print out2, fmt("inside table_expire_func: [%s, %s], %s", s, s2, tt[s, s2, s3]);

	if ( tt[s, s2, s3] < 10 )
		return .1 secs ;

	schedule .1sec { die() };
	return 0 secs;
	}

event zeek_init()
	{
	local s = "ashish";
	t[s] = 1 ;
	tt[s, s, s] = 1;
	print fmt("starting: %s, %s", s, t[s]);
	print fmt("starting: %s, %s", s, tt[s, s, s]);
	}
