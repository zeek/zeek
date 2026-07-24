##! Analyze DHCPv6 (:rfc:`8415`) traffic and produce a ``dhcpv6.log`` organized
##! around a DHCPv6 "transaction": the messages exchanged between clients and
##! servers that share a transaction identifier. Because DHCPv6 uses multicast
##! and separate client/server flows, a single transaction involves multiple
##! UDP messages

@load base/frameworks/cluster
@load ./consts

module DHCPv6;

export {
    redef enum Log::ID += { LOG };

    ## Well-known DHCPv6 server ports (547/udp) and client ports (546/udp).
    const server_ports = { 547/udp } &redef;
    const client_ports = { 546/udp } &redef;

    global log_policy: Log::PolicyHook;

    ## The record type which contains the column fields of the DHCPv6 log.
	type Info: record {
		## The earliest time at which a message in this transaction was
		## observed.
		ts:                 time             &log;
		## The transaction identifier tying the exchange together.
		transaction_id:     count            &log;
		## Unique identifiers of the connections over which this
		## transaction was observed.
		uids:               set[string]      &log;

		## The most recent message type sent by a client.
		client_msg_type:    string           &log &optional;
		## The most recent message type sent by a server.
		server_msg_type:    string           &log &optional;
		## All message types observed in this transaction, in order.
		msg_types:          vector of string &log &default=vector();

		## The client DUID, formatted as ``<type>:<hex>``.
		client_duid:        string           &log &optional;
		## The server DUID, formatted as ``<type>:<hex>``.
		server_duid:        string           &log &optional;
		## Option names requested by the client (option ORO).
		requested_options:  vector of string &log &optional;

		## The IAID of the first IA_NA option seen.
		iaid:               count            &log &optional;
		## The address assigned by the server (first IA Address option).
		assigned_addr:      addr             &log &optional;
		## Preferred lifetime of the assigned address.
		preferred_lifetime: interval         &log &optional;
		## Valid lifetime of the assigned address.
		valid_lifetime:     interval         &log &optional;

		## Status code name returned by the server (option STATUS_CODE).
		status:             string           &log &optional;
		## Status message returned by the server (option STATUS_CODE).
		status_message:     string           &log &optional;
		## FQDN provided by the client (option CLIENT_FQDN).
		client_fqdn:        string           &log &optional;

		## Duration from the first to the last message of the transaction.
		duration:           interval         &log &default=0secs;
	};

    ## Message types that originate from a DHCPv6 server. All others are
	## treated as client messages. See :rfc:`8415#section-7.3`.
	const server_message_types: set[count] = {
		2,  # ADVERTISE
		7,  # REPLY
		10, # RECONFIGURE
	} &redef;

    ## The maximum amount of time a transaction is tracked before its
	## aggregated record is written to the log.
	option DHCPv6::transaction_timeout = 30secs;

    ## This event is used internally to distribute messages to the manager
	## for aggregation, since DHCPv6 does not follow the normal "connection"
	## model used by most protocols. It can also be handled to extend the
	## DHCPv6 log.
	global DHCPv6::aggregate_msgs: event(ts: time, uid: string, msg: DHCPv6::MessageInfo);

	## Event that can be handled to access the DHCPv6 record as it is sent
	## on to the logging framework.
	global log_dhcpv6: event(rec: Info);
}

event zeek_init() &priority=5
	{
	Log::create_stream(DHCPv6::LOG, [$columns=Info, $ev=log_dhcpv6, $path="dhcpv6",
	                         $policy=log_policy]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_DHCPV6, server_ports, client_ports);
	}

@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )

function format_duid(duid_type: count, duid: string): string
	{
	return fmt("%s:%s", DHCPv6::duid_types[duid_type], bytestring_to_hexstr(duid));
	}

function write_transaction(t: table[count] of Info, transaction_id: count): interval
	{
	Log::write(DHCPv6::LOG, t[transaction_id]);
	return 0secs;
	}

## Transactions currently being aggregated, keyed by transaction identifier.
## Only maintained on the manager.
global transactions: table[count] of Info
	&write_expire=transaction_timeout &expire_func=write_transaction;

event DHCPv6::aggregate_msgs(ts: time, uid: string, msg: DHCPv6::MessageInfo)
    {
    local id = msg$transaction_id;

    if ( id !in transactions )
		transactions[id] = Info($ts=ts, $transaction_id=id);
    
    local info = transactions[id];

    add info$uids[uid];
    info$msg_types += DHCPv6::message_types[msg$msg_type];
    info$duration = ts - info$ts;

	# Some fields are uniquely supplied by client or server
    if ( msg$msg_type in DHCPv6::server_message_types )
		{
		info$server_msg_type = DHCPv6::message_types[msg$msg_type];
		if ( msg?$server_duid_type && msg?$server_duid )
			info$server_duid = format_duid(msg$server_duid_type, msg$server_duid);
		}
	else
		{
		info$client_msg_type = DHCPv6::message_types[msg$msg_type];
		if ( msg?$client_duid_type && msg?$client_duid )
			info$client_duid = format_duid(msg$client_duid_type, msg$client_duid);
		if ( msg?$client_fqdn )
			info$client_fqdn = msg$client_fqdn;
		if ( msg?$requested_options )
			{
			local names: vector of string;
			for ( _, o in msg$requested_options )
				names += option_types[o];
			info$requested_options = names;
			}
		}
    
    # Some fields can be supplied by either side; keep the first non-empty
	# value we see.
	if ( msg?$iaid && ! info?$iaid )
		info$iaid = msg$iaid;
	if ( msg?$assigned_addr && ! info?$assigned_addr )
		info$assigned_addr = msg$assigned_addr;
	if ( msg?$preferred_lifetime && ! info?$preferred_lifetime )
		info$preferred_lifetime = msg$preferred_lifetime * 1sec;
	if ( msg?$valid_lifetime && ! info?$valid_lifetime )
		info$valid_lifetime = msg$valid_lifetime * 1sec;
	if ( msg?$status_code && ! info?$status )
		{
		info$status = status_codes[msg$status_code];
		if ( msg?$status_message && |msg$status_message| > 0 )
			info$status_message = msg$status_message;
		}
    
    }

event zeek_done() &priority=-5
	{
	# Flush any transactions that never expired
	local recs: vector of Info;
	for ( id in transactions )
		recs += transactions[id];

	for ( _, r in recs )
		Log::write(DHCPv6::LOG, r);
	}

@endif

# On a worker, forward each message to the manager; otherwise aggregate locally.
event dhcpv6_message(c: connection, is_orig: bool, msg: DHCPv6::MessageInfo)
	{
	if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
		Cluster::publish(Cluster::manager_topic, DHCPv6::aggregate_msgs,
		                 network_time(), c$uid, msg);
	else
		event DHCPv6::aggregate_msgs(network_time(), c$uid, msg);
	}