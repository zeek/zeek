##! A very basic DNP3 analysis script that just logs requests and replies.

module DNP3;

@load ./consts

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Time of the request.
		ts:         time           &log;
		## Unique identifier for the connection.
		uid:        string         &log;
		## Identifier for the connection.
		id:         conn_id        &log;
		## The name of the function message in the request.
		fc_request: string         &log &optional;
		## The name of the function message in the reply.
		fc_reply:   string         &log &optional;
		## The response's "internal indication number".
		iin:        count          &log &optional;
	};

	## Event that can be handled to access the DNP3 record as it is sent on
	## to the logging framework.
	global log_dnp3: event(rec: Info);
}

redef record connection += {
	dnp3: Info &optional;
};

const ports = { 20000/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(DNP3::LOG, [$columns=Info, $ev=log_dnp3]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_DNP3, ports);
	}

event dnp3_application_request_header(c: connection, is_orig: bool, fc: count)
	{
	if ( ! c?$dnp3 )
		c$dnp3 = [$ts=network_time(), $uid=c$uid, $id=c$id];

	c$dnp3$ts = network_time();
	c$dnp3$fc_request = function_codes[fc];
	}

event dnp3_application_response_header(c: connection, is_orig: bool, fc: count, iin: count)
	{
	if ( ! c?$dnp3 )
		c$dnp3 = [$ts=network_time(), $uid=c$uid, $id=c$id];

	c$dnp3$ts = network_time();
	c$dnp3$fc_reply = function_codes[fc];
	c$dnp3$iin = iin;

	Log::write(LOG, c$dnp3);

	delete c$dnp3;
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( ! c?$dnp3 )
		return;

	Log::write(LOG, c$dnp3);
	delete c$dnp3;
	}
