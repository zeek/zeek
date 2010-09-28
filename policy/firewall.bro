# $Id: firewall.bro 4758 2007-08-10 06:49:23Z vern $
#
# Firewall-like rules.

@load notice
@load conn
@load ftp

module Firewall;

export {
	type action: enum { ALLOW, DENY };
	type cmp: enum { EQ, NE };

	type rule: record {
		label: string &default = "<no-label>";
		orig: subnet &default = 0.0.0.0/0;
		orig_set: set[addr] &optional;
		orig_cmp: cmp &default = EQ;
		orig_p: port &default = 0/tcp;
		orig_p_cmp: cmp &default = EQ;
		resp: subnet &default = 0.0.0.0/0;
		resp_set: set[addr] &optional;
		resp_cmp: cmp &default = EQ;
		resp_p: port &default = 0/tcp;
		resp_p_cmp: cmp &default = EQ;
		prot: transport_proto &default = unknown_transport;
		prot_cmp: cmp &default = EQ;
		state: string &default = "";
		state_cmp: cmp &default = EQ;
		is_ftp: bool &default = F;

		action: action &default = ALLOW;
	};

	redef enum Notice += {
		DenyRuleMatched
	};

	global begin: function(c: connection);
	global match_rule: function(c: connection, r: rule);
}

const log_file = open_log_file("firewall") &redef;

global stop_matching = F;

function do_match(c: connection, r: rule): bool
	{
	if ( r$orig_cmp == EQ )
		{
		if ( r?$orig_set )
			{
			if ( c$id$orig_h !in r$orig_set && c$id$orig_h !in r$orig )
				return F;
			}
		else
			{
			if ( c$id$orig_h !in r$orig )
				return F;
			}
		}
	else
		{
		if ( r?$orig_set )
			{
			if ( c$id$orig_h in r$orig_set || c$id$orig_h in r$orig )
				return F;
			}
		else
			{
			if ( c$id$orig_h in r$orig )
				return F;
			}
		}

	if ( r$resp_cmp == EQ )
		{
		if ( r?$resp_set )
			{
			if ( c$id$resp_h !in r$resp_set && c$id$resp_h !in r$resp )
				return F;
			}
		else
			{
			if ( c$id$resp_h !in r$resp )
				return F;
			}
		}
	else
		{
		if ( r?$resp_set )
			{
			if ( c$id$resp_h in r$resp_set || c$id$resp_h in r$resp )
				return F;
			}
		else
			{
			if ( c$id$resp_h in r$resp )
				return F;
			}
		}

	if ( r$orig_p != 0/tcp )
		{
		if ( r$orig_p_cmp == EQ )
			{
			if ( c$id$orig_p != r$orig_p )
				return F;
			}
		else
			if ( c$id$orig_p == r$orig_p )
				return F;
		}

	if ( r$resp_p != 0/tcp )
		{
		if ( r$resp_p_cmp == EQ )
			{
			if ( c$id$resp_p != r$resp_p )
				return F;
			}
		else
			if ( c$id$resp_p == r$resp_p )
				return F;
		}

	if ( r$state != "" )
		{
		local state = conn_state(c, get_port_transport_proto(c$id$orig_p));
		if ( r$state_cmp == EQ )
			{
			if ( state != r$state )
				return F;
			}
		else
			if ( state == r$state )
				return F;
		}

	if ( r$prot != unknown_transport )
		{
		local proto = get_port_transport_proto(c$id$orig_p);
		if ( r$prot_cmp == EQ )
			{
			if ( proto != r$prot )
				return F;
			}
		else
			if ( proto == r$prot )
				return F;
		}

	if ( r$is_ftp && ! is_ftp_data_conn(c) )
		return F;

	return T;
	}


function report_violation(c: connection, r:rule)
	{
	local trans = get_port_transport_proto(c$id$orig_p);
	local state = conn_state(c, trans);

	NOTICE([$note=DenyRuleMatched,
			$msg=fmt("%s %s",
		 	id_string(c$id), trans), $conn=c, $sub=r$label]);
	append_addl(c, fmt("<%s>", r$label));
	record_connection(log_file, c);
	}

function begin(c: connection)
	{
	stop_matching = F;
	}

function match_rule(c: connection, r: rule)
	{
	if ( stop_matching )
		return;

	if ( do_match(c, r) )
		{
		stop_matching = T;

		if ( r$action == DENY )
			report_violation(c, r);
		}
	}

event bro_init()
	{
	set_buf(log_file, F);
	}
