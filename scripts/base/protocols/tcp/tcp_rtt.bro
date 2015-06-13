@load base/protocols/conn

redef use_tcp_analyzer=T;

module TCPRTT;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record {
		ts:			time 	&log;
		uid:		string	&log;
		id:			conn_id	&log;

		label:		string  &log;
		
		rtt:		double	&log &optional;
		rto:		double 	&log &optional;
		is_orig:	bool	&log;
	};

	global log_tcp_rtt: event(rec: Info);
}



event bro_init() &priority=5
	{	
		Log::create_stream(TCPRTT::LOG, [$columns=Info]);
	}
	
event conn_initial_rto(	c: connection, 
					timestamp: time, 
					rto:double,
					is_orig:bool) &priority=-5
	{
		local rec: TCPRTT::Info = [	
			$ts = timestamp, 
			$uid = c$uid, 	
			$id = c$id,
			$label = "TCP::InitialRTO",
			$rto = rto,
			$is_orig = is_orig ];
		Log::write(TCPRTT::LOG, rec);
	}
	
event conn_initial_rtt(	c: connection, 
					timestamp: time, 
					rtt:double,
					is_orig:bool) &priority=-5
	{			
		local rec: TCPRTT::Info = [	
			$ts = timestamp, 
			$uid = c$uid, 	
			$id = c$id,
			$label = "TCP::InitialRTT",
			$rtt = rtt,
			$is_orig = is_orig ];
		Log::write(TCPRTT::LOG, rec);
	}