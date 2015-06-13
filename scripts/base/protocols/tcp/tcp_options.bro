redef use_tcp_analyzer=T;

module TCPOPTIONS;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record {
		ts:					time 	&log;
		uid:				string	&log;
		id:					conn_id	&log;
		label:				string	&log;
		timestamps:			bool	&log;
		bad:				bool	&log;
		sack_used:			bool	&log;
		orig_sack_offer:	bool	&log;
		resp_sack_offer:	bool	&log;
	};

	global log_tcp_options: event(rec: Info);
}

event bro_init() &priority=5
	{	
		Log::create_stream(TCPOPTIONS::LOG, [$columns=Info]);
	}

event conn_config(	
		c: connection, 
		timestamp: time, 
		ts:bool, 
		bad_conn:bool, 
		sack:bool, 
		o_sack_offer:bool, 
		r_sack_offer:bool) &priority=-5
	{
		local rec: TCPOPTIONS::Info = [	
			$ts   				= timestamp, 
			$uid  				= c$uid, 	
			$id   				= c$id,
			$label				= "TCP::Options",
			$timestamps 		= ts,
			$bad				= bad_conn,
			$sack_used			= sack, 
			$orig_sack_offer 	= o_sack_offer,
			$resp_sack_offer 	= r_sack_offer ];
        Log::write(TCPOPTIONS::LOG, rec);
	}