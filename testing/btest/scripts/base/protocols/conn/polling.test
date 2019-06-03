# @TEST-EXEC: zeek -b -r $TRACES/http/100-continue.trace %INPUT >out1
# @TEST-EXEC: btest-diff out1
# @TEST-EXEC: zeek -b -r $TRACES/http/100-continue.trace %INPUT stop_cnt=2 >out2
# @TEST-EXEC: btest-diff out2

@load base/protocols/conn

const stop_cnt = 10 &redef;

function callback(c: connection, cnt: count): interval
	{
	print "callback", c$id, cnt;
	return cnt >= stop_cnt ? -1 sec : .2 sec;
	}

event new_connection(c: connection)
	{
	print "new_connection", c$id;
	ConnPolling::watch(c, callback, 0, 0secs);
	}
