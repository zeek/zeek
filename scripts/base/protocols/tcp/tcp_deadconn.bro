@load base/protocols/conn
@load ./tcp_functions

redef use_tcp_analyzer=T;

module TCPDEADCONNECTION;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record {
		ts:			time 	&log;
		uid:		string	&log;
		id:			conn_id	&log;
		label:		string	&log;
		duration:	double	&log;
		state:          int     &log;
                #state:		string  &log;
		orig:		bool	&log;
	};

	global log_tcp_deadconnection: event(rec: Info);
}

event bro_init() &priority=5
	{	
		Log::create_stream(TCPDEADCONNECTION::LOG, [$columns=Info]);
	}

event conn_dead_event(	c: connection, 
						timestamp:time, 
						duration:double,
						state:int, 
						is_orig:bool) &priority=-5
	{
		local rec: TCPDEADCONNECTION::Info = [	
			$ts   		= timestamp, 
			$uid  		= c$uid, 	
			$id   		= c$id,
			$label		= "TCP::ConnectionFailure",
			$duration 	= duration,
                        $state          = state,
			#$state 		= state_string(	state ),
			$orig 		= is_orig ];
        Log::write(TCPDEADCONNECTION::LOG, rec);
	}