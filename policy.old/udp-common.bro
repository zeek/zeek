# $Id: udp-common.bro 4758 2007-08-10 06:49:23Z vern $
#
# Performs generic UDP request/reply processing, but doesn't set
# the packet filter to capture all UDP traffic (use udp.bro for that).

@load hot
@load conn
@load scan

global udp_req_count: table[conn_id] of count &default = 0;
global udp_rep_count: table[conn_id] of count &default = 0;

event udp_request(u: connection)
	{
	Scan::check_scan(u, F, F);
#	if ( TRW::use_TRW_algorithm )
#		TRW::check_TRW_scan(u, conn_state(u, udp), F);

	Hot::check_hot(u, Hot::CONN_ATTEMPTED);
	}

event udp_reply(u: connection)
	{
	Scan::check_scan(u, T, F);
#	if ( TRW::use_TRW_algorithm )
#		TRW::check_TRW_scan(u, conn_state(u, udp), F);

	Hot::check_hot(u, Hot::CONN_ESTABLISHED);
	Hot::check_hot(u, Hot::CONN_FINISHED);
	}

function add_req_rep_addl(u: connection)
	{
	local id = u$id;
	if ( udp_req_count[id] > 1 || udp_rep_count[id] > 1 )
		append_addl(u, fmt("[%d/%d]", udp_req_count[id], udp_rep_count[id]));

	delete udp_req_count[id];
	delete udp_rep_count[id];
	}

event udp_session_done(u: connection)
	{
	add_req_rep_addl(u);
	Hot::check_hot(u, Hot::CONN_FINISHED);
	}
