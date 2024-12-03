@load base/frameworks/cluster
@load ./consts

module DHCPv6;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type DUID: record {
		## Type of DUID in string format.
		typ: string;
		## DUID in hex format.
		data: string;
	} &log;

	type Status: record {
		code: string;
		message: string;
	} &log;

	type IA_NA: record {
		iaid: count &log &optional;
		t1: interval &log &optional;
		t2: interval &log &optional;
		iaaddr: addr &optional;  # This could be more than just one.
	} &log;

	## The record type which contains the column fields of the DHCP log.
	type Info: record {
		## The earliest time at which a DHCP message over the
		## associated connection is observed.
		ts: time &log;

		## Transaction ID.
		transaction_id: count &log;

		client_msg_type: string &log &optional;
		server_msg_type: string &log &optional;

		client_duid: DUID &log &optional;
		server_duid: DUID &log &optional;

		client_options: vector of string &log;
		client_requested_options: vector of string &log &optional;
		server_options: vector of string &log;


		## Involved connection uids for this transaction.
		uids: set[string] &log;

		## Information of the *first* ia_na option given
		## by the server.
		ia_na: IA_NA &log &optional;

		status: Status &log &optional;

		## If the server provided a jj
		client_fqdn: string &log &optional;

		logged: bool &default=F;
	};

	type State: record {
		info: Info;
		cid: conn_id;
		uid: string;
		is_client: bool;
	};

	## Event that can be handled to access the DHCP
	## record as it is sent on to the logging framework.
	global log_dhcpv6: event(rec: Info);

	option transaction_timeout = 5sec;

	global aggregate_msgs: event(c: State);
}

# Add the dhcp info to the connection record.
redef record connection += {
	dhcpv6_state: State &optional;
};

const ports = { 546/udp, 547/udp };
redef likely_server_ports += { 547/udp };

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_dhcpv6, $path="dhcpv6", $policy=log_policy]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_DHCPV6, ports);
	}

function do_log(tbl: table[count] of State, transaction_id: count): interval
	{
	local rec = tbl[transaction_id]$info;
	print "expire_func", rec;
	if ( ! rec$logged )
		{
		Log::write(LOG, rec);
		rec$logged = T;
		}

	return 0sec;
	}

## On manager, globally?
global transactions: table[count] of State &write_expire=transaction_timeout &expire_func=do_log;

function merge(into_state: State, from_state: State): Info
	{
	local into = into_state$info;
	local from = from_state$info;
	local from_is_client = from_state$is_client;
	local from_is_server = ! from_is_client;

	add into$uids[from_state$uid];

	if ( from_is_server )
		{
		if ( from?$status )
			into$status = from$status;

		if ( from?$server_msg_type )
			into$server_msg_type = from$server_msg_type;

		into$server_options = from$server_options;

		if ( from?$server_duid )
			into$server_duid = from$server_duid;

		if ( from?$ia_na )
			into$ia_na = from$ia_na;
		}

	return into;
	}

event aggregate_msgs(state: State)
	{
	local txid = state$info$transaction_id;
	print "aggregate", state$is_client;

	# First time we see this transaction, just store it.
	if ( txid !in transactions )
		{
		transactions[txid] = state;
		return;
		}

	local into_state = transactions[txid];
	if ( into_state$is_client == state$is_client )
		{
		# Repeated send from client or server. Is this weird?
		Weird::weird([$ts=network_time(), $uid=state$uid, $name="dhcpv6_resend"]);
		Log::write(LOG, into_state$info);
		transactions[txid] = state;
		}
	else
		{
		if ( ! into_state$is_client )
			Weird::weird([$ts=network_time(), $uid=into_state$uid, $name="dhcpv6_server_before_client"]);

		local info = merge(into_state, state);
		Log::write(LOG, info);

		# We do not delete the record immediately so that for a
		# single client request that doesn't use SERVERID, we
		# might process further replies.
		info$logged = T;
		}
	}

function set_state(c: connection, is_orig: bool, transaction_id: count): State
	{
	print "set_state", c$id, is_orig;
	c$dhcpv6_state = State($cid=c$id, $uid=c$uid, $is_client=is_orig);
	c$dhcpv6_state$info = Info($ts=network_time(), $transaction_id=transaction_id);
	add c$dhcpv6_state$info$uids[c$uid];

	return c$dhcpv6_state;
	}

# Aggregate DHCP messages to the manager.
event dhcpv6_message(c: connection, is_orig: bool, msg_type: count, transaction_id: count)
	{
	print "XXX dhcpv6_message", c$uid, c$id, is_orig, message_types[msg_type];
	local state = set_state(c, is_orig, transaction_id);
	if ( state$is_client )
		state$info$client_msg_type = message_types[msg_type];
	else
		state$info$server_msg_type = message_types[msg_type];
	# print "dhcpv6_message", c$uid, c$id, is_orig;
#	if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
#		Broker::publish(Cluster::manager_topic, DHCP::aggregate_msgs,
#		                network_time(), c$id, c$uid, is_orig, msg, options);
#	else
#		event DHCP::aggregate_msgs(network_time(), c$id, c$uid, is_orig, msg, options);
	}

event dhcpv6_option(c: connection, is_orig: bool, code: count)
	{
	print "option", option_types[code];
	local info = c$dhcpv6_state$info;
	local opts = c$dhcpv6_state$is_client ? info$client_options : info$server_options;
	opts += option_types[code];
	}

event dhcpv6_option_clientid(c: connection, is_orig: bool, duid_type: count, data: string)
	{
	local info = c$dhcpv6_state$info;
	info$client_duid = [$typ=duid_types[duid_type], $data=bytestring_to_hexstr(data)];
	}

event dhcpv6_option_serverid(c: connection, is_orig: bool, duid_type: count, data: string)
	{
	local info = c$dhcpv6_state$info;
	info$server_duid = [$typ=duid_types[duid_type], $data=bytestring_to_hexstr(data)];
	}

event dhcpv6_option_status_code(c: connection, is_orig: bool, code: count, message: string)
	{
	local info = c$dhcpv6_state$info;
	info$status = [$code=status_codes[code], $message=message];
	}

event dhcpv6_option_requested_options(c: connection, is_orig: bool, options: vector of count)
	{
	print "requested options", options;
	local vec: vector of string;
	for ( _, o in options )
		vec += option_types[o];

	c$dhcpv6_state$info$client_requested_options = vec;
	}

event dhcpv6_option_ia_na(c: connection, is_orig: bool, iaid: count, t1: interval, t2: interval)
	{
	local state = c$dhcpv6_state;
	local info = state$info;

	# Weird?
	if ( ! info?$ia_na )
		info$ia_na = IA_NA();

	local ia_na = state$info$ia_na;
	ia_na$iaid = iaid;
	ia_na$t1 = t1;
	ia_na$t2 = t2;
	}

event dhcpv6_option_ipaddr(c: connection, is_orig: bool, addr6: addr, preferred_lifetime: interval, valid_lifetime: interval)
	{
	local state = c$dhcpv6_state;
	if ( c$dhcpv6_state$is_client )
		{
		Weird::weird([$ts=network_time(), $uid=state$uid, $name="dhcpv6_ipaddr_option_from_client"]);
		return;
		}

	local info = state$info;
	info$ia_na = IA_NA($iaaddr=addr6);
	}

event dhcpv6_option_client_fqdn(c: connection, is_orig: bool, n: bool, o: bool, s: bool,
                                domain_name: string)
	{
	print "GGGGGRR client fqdn", "n", n, "o", o, "s", s, domain_name;
	}

event dhcpv6_message_end(c: connection, is_orig: bool, msg_type: count, transaction_id: count)
	{
	print "dhcpv6_message_end", c$uid, c$id, is_orig;

# TODO: Cluster, publish to manager
	event aggregate_msgs(c$dhcpv6_state);

	delete c$dhcpv6_state;
	}

event zeek_done() &priority=-5
	{
	# Log any remaining data that hasn't already been logged!
	# for ( i in DHCP::join_data )
	#	join_data_expiration(DHCP::join_data, i);
	}


hook log_policy(rec: Info, id: Log::ID, filter: Log::Filter)
	{
	print "log_policy", rec;
	}
