@load base/init-bare.bro

redef use_tcp_analyzer=T;

module TCPOSFP;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record {
		uid:		string	&log;
		id:			conn_id	&log;
		host:		addr	&log;
		genre:		string	&log &optional;
		detail:		string	&log &optional;
		dist:		count	&log &optional;
		OS:			OS_version &log;
	};

	global log_tcp_osfp: event(rec: Info);
}



event bro_init() &priority=5
	{	
		Log::create_stream(TCPOSFP::LOG, [$columns=Info]);
	}
	
event OS_version_found(c: connection, host: addr, OS: OS_version) &priority=-5
	{
		local rec: TCPOSFP::Info = [	
			$uid = c$uid, 	
			$id = c$id,
			$host = host,
			$genre = OS$genre,
			$detail = OS$detail,
			$dist = OS$dist,
			$OS = OS ];
		Log::write(TCPOSFP::LOG, rec);
	}