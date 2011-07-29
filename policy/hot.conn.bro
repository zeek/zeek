@load hot

redef enum Notice += {
	Sensitive_Connection,	# connection marked "hot"
};

# Whether to translate the local address in Sensitive_Connection notices
# to a hostname.  Meant as a demonstration of the "when" construct.
const xlate_hot_local_addr = F &redef;

# The sets are indexed by the complete hot messages.
global hot_conns_reported: table[conn_id] of set[string];

const conn_closed = { TCP_CLOSED, TCP_RESET };

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


# Low-level routine that generates the actual Sensitive_Connection
# notice associated with a "hot" connection.
function do_hot_notice(c: connection, dir: string, host: string)
	{
	NOTICE([$note=Sensitive_Connection, $conn=c,
		$msg=fmt("hot: %s %s local host: %s",
			full_id_string(c), dir, host)]);
	}

# Generate a Sensitive_Connection notice with the local hostname
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
			NOTICE([$note=Sensitive_Connection, $conn=c,
				$msg=fmt("hot: %s", full_id_string(c))]);

		add hot_conns_reported[c$id][msg];
		}
	}


event connection_established(c: connection)
	{
	Hot::check_hot(c, Hot::CONN_ESTABLISHED);

	if ( c$hot > 0 )
		log_hot_conn(c);
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

	delete hot_conns_reported[c$id];
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
