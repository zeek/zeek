# $Id: ident.bro 5948 2008-07-11 22:29:49Z vern $

@load notice
@load hot-ids

module Ident;

export {
	redef enum Notice += {
		IdentSensitiveID,	# sensitive username in Ident lookup
	};

	const hot_ident_ids = { always_hot_ids, } &redef;
	const hot_ident_exceptions = { "uucp", "nuucp", "daemon", } &redef;
}

redef capture_filters += { ["ident"] = "tcp port 113" };

global ident_ports = { 113/tcp } &redef;
redef dpd_config += { [ANALYZER_IDENT] = [$ports = ident_ports] };

global pending_ident_requests: set[addr, port, addr, port, port, port];

event ident_request(c: connection, lport: port, rport: port)
	{
	local id = c$id;
	add pending_ident_requests[id$orig_h, id$orig_p, id$resp_h, id$resp_p, lport, rport];
	}

function add_ident_tag(c: connection, lport: port, rport: port, tag: string)
: connection
	{
	local id = c$id;
	if ( [id$orig_h, id$orig_p, id$resp_h, id$resp_p, lport, rport] in
	     pending_ident_requests )
		delete pending_ident_requests[id$orig_h, id$orig_p, id$resp_h, id$resp_p, lport, rport];
	else
		tag = fmt("orphan-%s", tag);

	local c_orig_id = [$orig_h = id$resp_h, $orig_p = rport,
				$resp_h = id$orig_h, $resp_p = lport];

	local c_orig = active_connection(c_orig_id) ?
			connection_record(c_orig_id) : c;

	append_addl(c_orig, tag);

	return c_orig;
	}

event ident_reply(c: connection, lport: port, rport: port,
		user_id: string, system: string)
	{
	local c_orig = add_ident_tag(c, lport, rport, fmt("ident/%s", user_id));

	if ( user_id in hot_ident_ids && user_id !in hot_ident_exceptions )
		{
		++c_orig$hot;
		NOTICE([$note=IdentSensitiveID, $conn=c,
			$msg=fmt("%s hot ident: %s",
				$user=c_orig$addl, id_string(c_orig$id))]);
		}
	}

event ident_error(c: connection, lport: port, rport: port, line: string)
	{
	add_ident_tag(c, lport, rport, fmt("iderr/%s", line));
	}
