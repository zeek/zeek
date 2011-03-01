# $Id: conn.bro 6782 2009-06-28 02:19:03Z vern $

@load notice
@load hot
@load port-name
@load netstats
@load conn-id

redef enum Notice += {
	SensitiveConnection,	# connection marked "hot"
};

const conn_closed = { TCP_CLOSED, TCP_RESET };

global have_FTP = F;	# if true, we've loaded ftp.bro
global have_SMTP = F;	# if true, we've loaded smtp.bro
global is_ftp_data_conn: function(c: connection): bool;

# Whether to include connection state history in the logs generated
# by record_connection.
const record_state_history = F &redef;

# Whether to translate the local address in SensitiveConnection notices
# to a hostname.  Meant as a demonstration of the "when" construct.
const xlate_hot_local_addr = F &redef;

# Whether to use DPD for generating the service field in the summaries.
# Default off, because it changes the format of conn.log in a way
# potentially incompatible with existing scripts.
const dpd_conn_logs = F &redef;

# Maps a given port on a given server's address to an RPC service.
# If we haven't loaded portmapper.bro, then it will be empty
# (and, ideally, queries to it would be optimized away ...).
global RPC_server_map: table[addr, port] of string;

const conn_file = open_log_file("conn") &redef;

function conn_state(c: connection, trans: transport_proto): string
	{
	local os = c$orig$state;
	local rs = c$resp$state;

	local o_inactive = os == TCP_INACTIVE || os == TCP_PARTIAL;
	local r_inactive = rs == TCP_INACTIVE || rs == TCP_PARTIAL;

	if ( trans == tcp )
		{
		if ( rs == TCP_RESET )
			{
			if ( os == TCP_SYN_SENT || os == TCP_SYN_ACK_SENT ||
			     (os == TCP_RESET &&
			      c$orig$size == 0 && c$resp$size == 0) )
				return "REJ";
			else if ( o_inactive )
				return "RSTRH";
			else
				return "RSTR";
			}
		else if ( os == TCP_RESET )
			return r_inactive ? "RSTOS0" : "RSTO";
		else if ( rs == TCP_CLOSED && os == TCP_CLOSED )
			return "SF";
		else if ( os == TCP_CLOSED )
			return r_inactive ? "SH" : "S2";
		else if ( rs == TCP_CLOSED )
			return o_inactive ? "SHR" : "S3";
		else if ( os == TCP_SYN_SENT && rs == TCP_INACTIVE )
			return "S0";
		else if ( os == TCP_ESTABLISHED && rs == TCP_ESTABLISHED )
			return "S1";
		else
			return "OTH";
		}

	else if ( trans == udp )
		{
		if ( os == UDP_ACTIVE )
			return rs == UDP_ACTIVE ? "SF" : "S0";
		else
			return rs == UDP_ACTIVE ? "SHR" : "OTH";
		}

	else
		return "OTH";
	}

function conn_size(e: endpoint, trans: transport_proto): string
	{
	if ( e$size > 0 || (trans == tcp && e$state == TCP_CLOSED) )
		return fmt("%d", e$size);
	else
		### should return 0 for TCP_RESET that went through TCP_CLOSED
		return "?";
	}

function service_name(c: connection): string
	{
	local p = c$id$resp_p;

	if ( p in port_names )
		return port_names[p];
	else
		return "other";
	}

const state_graphic = {
	["OTH"] = "?>?", ["REJ"] = "[",
	["RSTO"] = ">]", ["RSTOS0"] = "}]", ["RSTR"] = ">[", ["RSTRH"] = "<[",
	["S0"] = "}", ["S1"] = ">", ["S2"] = "}2", ["S3"] = "}3",
	["SF"] = ">", ["SH"] = ">h", ["SHR"] = "<h",
};

function full_id_string(c: connection): string
	{
	local id = c$id;
	local trans = get_port_transport_proto(id$orig_p);
	local state = conn_state(c, trans);
	local state_gr = state_graphic[state];
	local service = service_name(c);

	if ( state == "S0" || state == "S1" || state == "REJ" )
		return fmt("%s %s %s/%s %s", id$orig_h, state_gr,
				id$resp_h, service, c$addl);

	else
		return fmt("%s %sb %s %s/%s %sb %.1fs %s",
			id$orig_h, conn_size(c$orig, trans),
			state_gr, id$resp_h, service,
			conn_size(c$resp, trans), c$duration, c$addl);
	}

# The sets are indexed by the complete hot messages.
global hot_conns_reported: table[conn_id] of set[string];

# Low-level routine that generates the actual SensitiveConnection
# notice associated with a "hot" connection.
function do_hot_notice(c: connection, dir: string, host: string)
	{
	NOTICE([$note=SensitiveConnection, $conn=c,
		$msg=fmt("hot: %s %s local host: %s",
			full_id_string(c), dir, host)]);
	}

# Generate a SensitiveConnection notice with the local hostname
# translated.  Mostly intended as a demonstration of using "when".
function gen_hot_notice_with_hostnames(c: connection)
	{
	local id = c$id;
	local inbound = is_local_addr(id$resp_h);
	local dir = inbound ? "to" : "from";
	local local_addr = inbound ? id$orig_h : id$resp_h;

	add_notice_tag(c);

	when ( local hostname = lookup_addr(local_addr) )
		do_hot_notice(c, dir, hostname);
	timeout 5 sec
		{ do_hot_notice(c, dir, fmt("%s", local_addr)); }
	}

function log_hot_conn(c: connection)
	{
	if ( c$id !in hot_conns_reported )
		hot_conns_reported[c$id] = set() &mergeable;

	local msg = full_id_string(c);

	if ( msg !in hot_conns_reported[c$id] )
		{
		if ( xlate_hot_local_addr )
			gen_hot_notice_with_hostnames(c);
		else
			NOTICE([$note=SensitiveConnection, $conn=c,
				$msg=fmt("hot: %s", full_id_string(c))]);

		add hot_conns_reported[c$id][msg];
		}
	}

function determine_service_non_DPD(c: connection) : string
	{
	if ( length(c$service) != 0 )
		{
		for ( i in c$service )
			return i;	# return first;
		}

	else if ( have_FTP && is_ftp_data_conn(c) )
		return port_names[20/tcp];

	else if ( [c$id$resp_h, c$id$resp_p] in RPC_server_map )
		# Alternatively, perhaps this should be stored in $addl
		# rather than $service, so the port number remains
		# visible .... ?
		return RPC_server_map[c$id$resp_h, c$id$resp_p];

	else if ( c$orig$state == TCP_INACTIVE )
		{
		# We're seeing a half-established connection.  Use the
		# service of the originator if it's well-known and the
		# responder isn't.
		if ( c$id$resp_p !in port_names && c$id$orig_p in port_names )
			return port_names[c$id$orig_p];
		}

	return service_name(c);
	}

function determine_service(c: connection) : string
	{
	if ( ! dpd_conn_logs )
		return determine_service_non_DPD(c);

	if ( [c$id$resp_h, c$id$resp_p] in RPC_server_map )
		add c$service[RPC_server_map[c$id$resp_h, c$id$resp_p]];

	if ( length(c$service) == 0  )
		{
		# Empty service set.  Use port as a hint.
		if ( c$orig$state == TCP_INACTIVE )
			{
			# We're seeing a half-established connection.  Use the
			# service of the originator if it's well-known and the
			# responder isn't.
			if ( c$id$resp_p !in port_names &&
			     c$id$orig_p in port_names )
				return fmt("%s?", port_names[c$id$orig_p]);
			}

		if ( c$id$resp_p in port_names )
			return fmt("%s?", port_names[c$id$resp_p]);

		return "other";
		}

	local service = "";
	for ( s in c$service )
		{
		if ( sub_bytes(s, 0, 1) != "-" )
			service = service == "" ? s : cat(service, ",", s);
		}

	return service != "" ? to_lower(service) : "other";
	}

function record_connection(f: file, c: connection)
	{
	local id = c$id;
	local local_init = is_local_addr(id$orig_h);

	local local_addr = local_init ? id$orig_h : id$resp_h;
	local remote_addr = local_init ? id$resp_h : id$orig_h;

	local flags = local_init ? "L" : "X";

	local trans = get_port_transport_proto(id$orig_p);
	local duration: string;

	# Do this first so we see the tag in addl.
	if ( c$hot > 0 )
		log_hot_conn(c);

	if ( trans == tcp )
		{
		if ( c$orig$state in conn_closed || c$resp$state in conn_closed )
			duration = fmt("%.06f", c$duration);
		else
			duration = "?";
		}
	else
		duration = fmt("%.06f", c$duration);

	local addl = c$addl;

@ifdef ( estimate_flow_size_and_remove )
	# Annotate connection with separately-estimated size, if present.
	local orig_est = estimate_flow_size_and_remove(id, T);
	local resp_est = estimate_flow_size_and_remove(id, F);

	if ( orig_est$have_est )
		addl = fmt("%s olower=%.0fMB oupper=%.0fMB oincon=%s", addl,
				orig_est$lower / 1e6, orig_est$upper / 1e6,
				orig_est$num_inconsistent);

	if ( resp_est$have_est )
		addl = fmt("%s rlower=%.0fMB rupper=%.0fMB rincon=%s", addl,
				resp_est$lower / 1e6, resp_est$upper / 1e6,
				resp_est$num_inconsistent);
@endif

	local service = determine_service(c);

	local log_msg =
		fmt("%.6f %s %s %s %s %d %d %s %s %s %s %s",
			c$start_time, duration, id$orig_h, id$resp_h, service,
			id$orig_p, id$resp_p, trans,
			conn_size(c$orig, trans), conn_size(c$resp, trans),
			conn_state(c, trans), flags);

	if ( record_state_history )
		log_msg = fmt("%s %s", log_msg,
				c$history == "" ? "X" : c$history);

	if ( addl != "" )
		log_msg = fmt("%s %s", log_msg, addl);

	print f, log_msg;
	}

event protocol_confirmation(c: connection, atype: count, aid: count)
	{
	if ( ! dpd_conn_logs )
		return;

	delete c$service[fmt("-%s",analyzer_name(atype))];
	add c$service[analyzer_name(atype)];
	}

event protocol_violation(c: connection, atype: count, aid: count,
				reason: string) &priority = 10
	{
	if ( ! dpd_conn_logs )
		return;

	delete c$service[analyzer_name(atype)];
	add c$service[fmt("-%s",analyzer_name(atype))];
	}

event connection_established(c: connection)
	{
	Hot::check_hot(c, Hot::CONN_ESTABLISHED);

	if ( c$hot > 0 )
		log_hot_conn(c);
	}

event partial_connection(c: connection)
	{
	if ( c$orig$state == TCP_PARTIAL && c$resp$state == TCP_INACTIVE )
		# This appears to be a stealth scan.  Don't do hot-checking
		# as there wasn't an established connection.
		;
	else
		{
		Hot::check_hot(c, Hot::CONN_ESTABLISHED);
		Hot::check_hot(c, Hot::APPL_ESTABLISHED);	# assume it's been established
		}

	if ( c$hot > 0 )
		log_hot_conn(c);
	}

event connection_attempt(c: connection)
	{
	Hot::check_spoof(c);
	Hot::check_hot(c, Hot::CONN_ATTEMPTED);
	}

event connection_finished(c: connection)
	{
	if ( c$orig$size == 0 || c$resp$size == 0 )
		# Hard to get excited about this - not worth logging again.
		c$hot = 0;
	else
		Hot::check_hot(c, Hot::CONN_FINISHED);
	}

event connection_partial_close(c: connection)
	{
	if ( c$orig$size == 0 || c$resp$size == 0 )
		# Hard to get excited about this - not worth logging again.
		c$hot = 0;
	else
		Hot::check_hot(c, Hot::CONN_FINISHED);
	}

event connection_half_finished(c: connection)
	{
	Hot::check_hot(c, Hot::CONN_ATTEMPTED);
	}

event connection_rejected(c: connection)
	{
	Hot::check_hot(c, Hot::CONN_REJECTED);
	}

event connection_reset(c: connection)
	{
	Hot::check_hot(c, Hot::CONN_FINISHED);
	}

event connection_pending(c: connection)
	{
	if ( c$orig$state in conn_closed &&
	     (c$resp$state == TCP_INACTIVE || c$resp$state == TCP_PARTIAL) )
		# This is a stray FIN or RST - don't bother reporting.
		return;

	if ( c$orig$state == TCP_RESET || c$resp$state == TCP_RESET )
		# We already reported this connection when the RST
		# occurred.
		return;

	Hot::check_hot(c, Hot::CONN_FINISHED);
	}

function connection_gone(c: connection, gone_type: string)
	{
	if ( c$orig$size == 0 || c$resp$size == 0 )
		{
		if ( c$orig$state == TCP_RESET && c$resp$state == TCP_INACTIVE)
			# A bare RST, no other context.  Ignore it.
			return;

		# Hard to get excited about this - not worth logging again,
		# per connection_finished().
		c$hot = 0;
		}
	else
		Hot::check_hot(c, Hot::CONN_TIMEOUT);
	}

event connection_state_remove(c: connection) &priority = -10
	{
	local os = c$orig$state;
	local rs = c$resp$state;

	if ( os == TCP_ESTABLISHED && rs == TCP_ESTABLISHED )
		# It was still active, no summary generated.
		connection_gone(c, "remove");

	else if ( (os == TCP_CLOSED || rs == TCP_CLOSED) &&
		  (os == TCP_ESTABLISHED || rs == TCP_ESTABLISHED) )
		# One side has closed, the other hasn't - it's in state S2
		# or S3, hasn't been reported yet.
		connection_gone(c, "remove");

	record_connection(conn_file, c);

	delete hot_conns_reported[c$id];
	}
