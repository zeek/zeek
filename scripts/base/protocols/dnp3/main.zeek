##! A very basic DNP3 analysis script that just logs requests and replies.

@load ./consts
@load base/protocols/conn/removal-hooks

module DNP3;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

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

	## DNP3 finalization hook.  Remaining DNP3 info may get logged when it's called.
	global finalize_dnp3: Conn::RemovalHook;
}

redef record connection += {
	dnp3: Info &optional;
};

const ports = { 20000/tcp , 20000/udp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(DNP3::LOG, [$columns=Info, $ev=log_dnp3, $path="dnp3", $policy=log_policy]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_DNP3_TCP, ports);
	}

event dnp3_application_request_header(c: connection, is_orig: bool, application_control: count, fc: count)
	{
	if ( ! c?$dnp3 )
		{
		c$dnp3 = [$ts=network_time(), $uid=c$uid, $id=c$id];
		Conn::register_removal_hook(c, finalize_dnp3);
		}

	c$dnp3$ts = network_time();
	c$dnp3$fc_request = function_codes[fc];
	}

event dnp3_application_response_header(c: connection, is_orig: bool, application_control: count, fc: count, iin: count)
	{
	if ( ! c?$dnp3 )
		{
		c$dnp3 = [$ts=network_time(), $uid=c$uid, $id=c$id];
		Conn::register_removal_hook(c, finalize_dnp3);
		}

	c$dnp3$ts = network_time();
	c$dnp3$fc_reply = function_codes[fc];
	c$dnp3$iin = iin;

	Log::write(LOG, c$dnp3);

	delete c$dnp3;
	}

hook finalize_dnp3(c: connection)
	{
	if ( ! c?$dnp3 )
		return;

	Log::write(LOG, c$dnp3);
	delete c$dnp3;
	}
