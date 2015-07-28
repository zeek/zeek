##! Facilitates connecting to remote Bro or Broccoli instances to share state
##! and/or transfer events.

@load base/frameworks/packet-filter
@load base/utils/addrs

module Communication;

export {

	## The communication logging stream identifier.
	redef enum Log::ID += { LOG };

	## Which interface to listen on. The addresses ``0.0.0.0`` and ``[::]``
	## are wildcards.
	const listen_interface = 0.0.0.0 &redef;

	## Which port to listen on.  Note that BroControl sets this
	## automatically.
	const listen_port = 47757/tcp &redef;

	## This defines if a listening socket should use SSL.
	const listen_ssl = F &redef;

	## Defines if a listening socket can bind to IPv6 addresses.
	##
	## Note that this is overridden by the BroControl IPv6Comm option.
	const listen_ipv6 = F &redef;

	## If :bro:id:`Communication::listen_interface` is a non-global
	## IPv6 address and requires a specific :rfc:`4007` ``zone_id``,
	## it can be specified here.
	const listen_ipv6_zone_id = "" &redef;

	## Defines the interval at which to retry binding to
	## :bro:id:`Communication::listen_interface` on
	## :bro:id:`Communication::listen_port` if it's already in use.
	const listen_retry = 30 secs &redef;

	## Default compression level.  Compression level is 0-9, with 0 = no
	## compression.
	global compression_level = 0 &redef;

	## A record type containing the column fields of the communication log.
	type Info: record {
		## The network time at which a communication event occurred.
		ts:                  time   &log;
		## The peer name (if any) with which a communication event is
		## concerned.
		peer:                string &log &optional;
		## Where the communication event message originated from, that
		## is, either from the scripting layer or inside the Bro process.
		src_name:            string &log &optional;
		## .. todo:: currently unused.
		connected_peer_desc: string &log &optional;
		## .. todo:: currently unused.
		connected_peer_addr: addr   &log &optional;
		## .. todo:: currently unused.
		connected_peer_port: port   &log &optional;
		## The severity of the communication event message.
		level:               string &log &optional;
		## A message describing the communication event between Bro or
		## Broccoli instances.
		message:             string &log;
	};

	## A remote peer to which we would like to talk.
	## If there's no entry for a peer, it may still connect
	## and request state, but not send us any.
	type Node: record {
		## Remote address.
		host: addr;

		## If the *host* field is a non-global IPv6 address, this field
		## can specify a particular :rfc:`4007` ``zone_id``.
		zone_id: string &optional;

		## Port of the remote Bro communication endpoint if we are
		## initiating the connection (based on the *connect* field).
		p: port &optional;

		## When accepting a connection, the configuration only
		## applies if the class matches the one transmitted by
		## the peer.
		##
		## When initiating a connection, the class is sent to
		## the other side.
		class: string &optional;

		## Events requested from remote side.
		events: set[string] &optional;

		## Whether we are going to connect (rather than waiting
		## for the other side to connect to us).
		connect: bool &default = F;

		## If disconnected, reconnect after this many seconds.
		retry: interval &default = 0 secs;

		## Whether to accept remote events.
		accept_input: bool &default = T;

		## Whether to perform state synchronization with peer.
		sync: bool &default = F;

		## Whether to request logs from the peer.
		request_logs: bool &default = F;

		## When performing state synchronization, whether we consider
		## our state to be authoritative (only one side can be
		## authoritative).  If so, we will send the peer our current
		## set when the connection is set up.
		auth: bool &default = F;

		## If not set, no capture filter is sent.
		## If set to an empty string, then the default capture filter
		## is sent.
		capture_filter: string &optional;

		## Whether to use SSL-based communication.
		ssl: bool &default = F;

		## Compression level is 0-9, with 0 = no compression.
		compression: count &default = compression_level;

		## The remote peer.
		peer: string &optional;

		## Indicates the status of the node.
		connected: bool &default = F;

	};

	## The table of Bro or Broccoli nodes that Bro will initiate connections
	## to or respond to connections from.  Note that BroControl sets this
	## automatically.
	global nodes: table[string] of Node &redef;

	## A table of peer nodes for which this node issued a
	## :bro:id:`Communication::connect_peer` call but with which a connection
	## has not yet been established or with which a connection has been
	## closed and is currently in the process of retrying to establish.
	## When a connection is successfully established, the peer is removed
	## from the table.
	#global pending_peers: table[peer_id] of Node;
	global pending_peers: table[string] of Node;

	## A table of peer nodes for which this node has an established connection.
	## Peers are automatically removed if their connection is closed and
	## automatically added back if a connection is re-established later.
	#global connected_peers: table[peer_id] of Node;
	global connected_peers: table[string] of Node;

	## Connect to a node in :bro:id:`Communication::nodes` independent
	## of its "connect" flag.
	##
	## peer: the string used to index a particular node within the
	##      :bro:id:`Communication::nodes` table.
	global connect_peer: function(peer: string);

	global reconnect_interval: interval = 1 secs;


	# Event that signals that we have finished the connection setup to a remote peer
	global outgoing_connection_established_event: event(peer_name: string);
}

const src_names = {
	[REMOTE_SRC_CHILD]  = "child",
	[REMOTE_SRC_PARENT] = "parent",
	[REMOTE_SRC_SCRIPT] = "script",
};

event bro_init() &priority=5
	{
	Log::create_stream(Communication::LOG, [$columns=Info, $path="communication"]);
	}

function do_script_log_common(peer_name: string, level: count, src: count, msg: string)
	{
	Log::write(Communication::LOG, [$ts = network_time(),
	                                $level = (level == REMOTE_LOG_INFO ? "info" : "error"),
	                                $src_name = src_names[src],
	                                $peer = peer_name,
	                                $message = msg]);
	}

function do_script_log(p: string, msg: string)
	{
	do_script_log_common(p, REMOTE_LOG_INFO, REMOTE_SRC_SCRIPT, msg);
	}

function connect_peer(peer: string)
	{
	local node = nodes[peer];
	local p = listen_port;

	# obtain port
	if ( node?$p )
		p = node$p;

	# ...and connect via broker
	local succ = BrokerComm::connect(fmt("%s", node$host), p, Communication::reconnect_interval);
	
	if ( !succ )
		Log::write(Communication::LOG, [$ts = network_time(),
		                                $peer = peer,
		                                $message = "can't trigger connect"]);
	pending_peers[peer] = node;
	}

function broker_request_events(be: set[string])
	{
		for ( e in be )
			BrokerComm::auto_event("/bro/event/cluster/worker/request", lookup_ID(e));
	}

#function setup_peer(p: event_peer, node: Node)
#	{
#	if ( node?$events ) # Done in listen.bro
#		{
#		do_script_log(p, fmt("requesting events matching %s", node$events));
#		request_remote_events(p, node$events);
#		}

#	if ( node?$capture_filter && node$capture_filter != "" ) # TODO
#		{
#		local filter = node$capture_filter;
#		do_script_log(p, fmt("sending capture_filter: %s", filter));
#		send_capture_filter(p, filter);
#		}

#	if ( node$accept_input ) # FIXME Required?
#		{
#		do_script_log(p, "accepting state");
#		set_accept_state(p, T);
#		}
#
#	set_compression_level(p, node$compression);

#	if ( node$sync )
#		{
#		do_script_log(p, "requesting synchronized state");
#		request_remote_sync(p, node$auth);
#		}

#	if ( node$request_logs ) # TODO needs to be implemented in listen.bro
#		{
#		do_script_log(p, "requesting logs");
#		request_remote_logs(p);
#		}

#	node$peer = p;
#	node$connected = T;
#	connected_peers[p] = node;
#	}

function setup_peer(peer_name: string, node: Node)
    {
	node$peer = peer_name;
    #node$zone_id = "1";
	node$connected = T;
    nodes[peer_name] = node;
	connected_peers[peer_name] = node;
    }

event BrokerComm::incoming_connection_established(peer_name: string)
	{
	print "BrokerComm::incoming_connection_established by", peer_name;
	do_script_log(peer_name, fmt("%s:incoming connection established", peer_name));
    local node = nodes[peer_name];
    setup_peer(peer_name, node);
	}

event BrokerComm::incoming_connection_broken(peer_name: string)
	{
	print "Incoming connection broken to", peer_name;
	}

event BrokerComm::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
	{
	print "BrokerComm::outgoing_connection_established to", peer_address, peer_port, peer_name;
	local id = fmt("%s:%s", peer_address, peer_port);
	local node = pending_peers[peer_name];
	delete pending_peers[peer_name];	
	do_script_log(peer_name, fmt("%s:connection established", peer_name));

    setup_peer(peer_name, node);

	event outgoing_connection_established_event(peer_name);
	}

event BrokerComm::outgoing_connection_broken(peer_address: string, peer_port: port, peer_name: string)
	{
	print "Outgoing connection broken to", peer_name, "from ", peer_address, "port", peer_port;
	do_script_log(peer_name, "connection closed/broken");

	if ( peer_name in connected_peers )
		{
		local node = connected_peers[peer_name];
		node$connected = F;
		delete connected_peers[peer_name];

		if ( reconnect_interval != 0secs )
			{
			# Broker will retry.
			pending_peers[peer_name] = nodes[peer_name];
			} 
		}
	}

event BrokerComm::outgoing_connection_incompatible(peer_address: string, peer_port: port, peer_name: string)
	{
	print "Outgoing connection incompatible to", peer_address;
	do_script_log(peer_name, "outgoind connection incompatible");
	}

# Actually initiate the connections that need to be established.
event bro_init() &priority = -10 # let others modify nodes
	{
	if ( |nodes| > 0 )
		enable_communication();

	for ( tag in nodes )
		{
		if ( ! nodes[tag]$connect )
			next;

		connect_peer(tag);
		}
	}
