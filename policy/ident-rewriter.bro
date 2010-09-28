# $Id: ident-rewriter.bro 47 2004-06-11 07:26:32Z vern $

@load ident

redef rewriting_ident_trace = T;

global public_ident_user_ids = { "root", } &redef;
global public_ident_systems = { "UNIX", } &redef;

const delay_rewriting_request = T;

function public_ident_user(id: string): bool
	{
	return id in public_ident_user_ids;
	}

function public_system(system: string): bool
	{
	return system in public_ident_systems;
	}

type ident_req: record {
	lport: port;
	rport: port;
	rewrite_slot: count;
};

# Does not support pipelining ....
global ident_req_slots: table[addr, port, addr, port] of ident_req;

event ident_request(c: connection, lport: port, rport: port)
	{
	if ( ! rewriting_trace() )
		return;

	local id = c$id;
	if ( delay_rewriting_request )
		{
		local slot = reserve_rewrite_slot(c);
		ident_req_slots[id$orig_h, id$orig_p, id$resp_h, id$resp_p] =
			[$lport = lport, $rport = rport, $rewrite_slot = slot];
		}
	else
		rewrite_ident_request(c, lport, rport);
	}

event ident_reply(c: connection, lport: port, rport: port,
		user_id: string, system: string)
	{
	if ( ! rewriting_trace() )
		return;

	local id = c$id;

	if ( [id$orig_h, id$orig_p, id$resp_h, id$resp_p] in ident_req_slots )
		{
		local req = ident_req_slots[id$orig_h, id$orig_p,
						id$resp_h, id$resp_p];

		seek_rewrite_slot(c, req$rewrite_slot);
		rewrite_ident_request(c, req$lport, req$rport);
		release_rewrite_slot(c, req$rewrite_slot);

		delete ident_req_slots[id$orig_h, id$orig_p,
					id$resp_h, id$resp_p];
		}

	rewrite_ident_reply(c, lport, rport,
			public_system(system) ? system : "OTHER",
			public_ident_user(user_id) ? user_id : "private user");
	}

event ident_error(c: connection, lport: port, rport: port, line: string)
	{
	if ( ! rewriting_trace() )
		return;

	local id = c$id;

	if ( [id$orig_h, id$orig_p, id$resp_h, id$resp_p] in ident_req_slots )
		{
		local req = ident_req_slots[id$orig_h, id$orig_p,
						id$resp_h, id$resp_p];

		seek_rewrite_slot(c, req$rewrite_slot);
		rewrite_ident_request(c, req$lport, req$rport);
		release_rewrite_slot(c, req$rewrite_slot);

		delete ident_req_slots[id$orig_h, id$orig_p,
					id$resp_h, id$resp_p];
		}

	rewrite_ident_error(c, lport, rport, line);
	}

event connection_state_remove(c: connection)
	{
	if ( ! rewriting_trace() )
		return;

	local id = c$id;

	if ( [id$orig_h, id$orig_p, id$resp_h, id$resp_p] in ident_req_slots )
		{
		local req = ident_req_slots[id$orig_h, id$orig_p,
						id$resp_h, id$resp_p];

		seek_rewrite_slot(c, req$rewrite_slot);
		rewrite_ident_request(c, req$lport, req$rport);
		release_rewrite_slot(c, req$rewrite_slot);

		delete ident_req_slots[id$orig_h, id$orig_p,
					id$resp_h, id$resp_p];
		}
	}
