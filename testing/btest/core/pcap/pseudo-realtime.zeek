# @TEST-EXEC: zeek -C -r $TRACES/wikipedia.trace %INPUT --pseudo-realtime >output
# @TEST-EXEC: btest-diff output

global init = F;
global last_network = network_time();
global last_current = current_time();
global cnt = 0;
global an = 0secs;
global ac = 0secs;

event new_packet(c: connection, p: pkt_hdr)
	{
	local tn = network_time();
	local tc = current_time();
	local dn = tn - last_network;
	local dc = tc - last_current;

	last_network = tn;
	last_current = tc;
	++cnt;

	if ( ! init ) 
		{
		init = T;
		return;
		}

	an += dn;
	ac += dc;
	
	# print fmt("num=%d agg_delta_network=%.1f agg_delta_real=%.1f", cnt, an, ac);
	}

event zeek_done()
	{
	local d = (an - ac);
	if ( d < 0 secs)
		d = -d;
	
	print fmt("real time %s trace time", d < 1.0secs ? "matches" : "does NOT match");
	}

