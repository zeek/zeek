# $Id: capture-unknown-protocols.bro 6811 2009-07-06 20:41:10Z robin $
#
# Capture the content of connections running a "foreign" protocol 
# on a well-known port.

module CaptureProtocolViolations;
	
@load site
@load tm-mail-contents
	
export {
	# We capture contents only for this subset of analyzers.
	const analyzers: set[AnalyzerTag] = 
		{ ANALYZER_SSH, ANALYZER_FTP, ANALYZER_SMTP, ANALYZER_POP3 } &redef;

	# If true, capture only outgoing connections.
	const outbound_only = F &redef;	

	global mail_proto_violation: function(c: connection, atype: count, reason: string, destination: string);
}

global reported: set[addr,addr,count] &read_expire = 24hr &persistent;

type violation_info: record {
	atype: count;
	reason: string;
	start: time;
	service: string;
	destination: string;
};

# We postpone the mail until the connection is done so that we
# can determine the real service.
global conn_expire_func: function(t: table[conn_id] of violation_info, id: conn_id): interval;
global mail_when_done: table[conn_id] of violation_info &create_expire=5mins &expire_func=conn_expire_func;

function end_of_connection(id: conn_id)
	{
	local info = mail_when_done[id];
	delete mail_when_done[id];
	
	local aname = analyzer_name(info$atype);

	local service = info$service;
	
	if ( service != "other" )
		service = to_upper(service);

	local subject = fmt("%s -> %s: %s protocol on %s port %s",
						id$orig_h, id$resp_h, service, aname, id$resp_p);
	
	local body = fmt("> %D %s@@@@Not %s: %s", info$start, id_string(id), aname, info$reason);
	
	TimeMachine::mail_contents(id, info$start, fmt("proto-violation.%s", aname), subject, body, info$destination);
	}

function conn_expire_func(t: table[conn_id] of violation_info, id: conn_id): interval
	{
	end_of_connection(id);
	print "conn_expire_func", id;
	return 0secs;
	}

event connection_state_remove(c: connection)
	{
	local id=c$id;
	
	if ( id !in mail_when_done )
		return;
	
	mail_when_done[id]$service = determine_service(c);
	
	end_of_connection(c$id);
	}

function mail_proto_violation(c: connection, atype: count, reason: string, destination: string)
	{
	if ( [c$id$orig_h, c$id$resp_h, atype] in reported )
		return;
	
	# Interesting analyzer?
	if ( atype !in analyzers )
		return;

	# Outbound connection?
	if ( outbound_only && is_local_addr(c$id$resp_h) )
		return;
	
	# Well-known port?
	if ( atype !in dpd_config || c$id$resp_p !in dpd_config[atype]$ports )
		return;

	mail_when_done[c$id] = [$atype=atype, $reason=reason, $destination=destination, $service=determine_service(c), $start=c$start_time];
	add reported[c$id$orig_h, c$id$resp_h, atype];
	}
