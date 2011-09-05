##! Core script support for logging syslog messages.

@load ./consts

module Syslog;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record {
		ts:        time            &log;
		uid:       string          &log;
		id:        conn_id         &log;
		proto:     transport_proto &log;
		facility:  string          &log;
		severity:  string          &log;
		message:   string          &log;
	};
	
	const ports = { 514/udp } &redef;
}

redef capture_filters += { ["syslog"] = "port 514" };
redef dpd_config += { [ANALYZER_SYSLOG_BINPAC] = [$ports = ports] };

redef record connection += {
	syslog: Info &optional;
};

event bro_init() &priority=5
	{
	Log::create_stream(Syslog::LOG, [$columns=Info]);
	}

event syslog_message(c: connection, facility: count, severity: count, msg: string) &priority=5
	{
	local info: Info;
	info$ts=network_time();
	info$uid=c$uid;
	info$id=c$id;
	info$proto=get_port_transport_proto(c$id$resp_p);
	info$facility=facility_codes[facility];
	info$severity=severity_codes[severity];
	info$message=msg;
	
	c$syslog = info;
	}

event syslog_message(c: connection, facility: count, severity: count, msg: string) &priority=-5
	{
	Log::write(Syslog::LOG, c$syslog);
	}
