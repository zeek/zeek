##! Facilitates connecting to remote Bro or Broker instances to share state
##! and/or transfer events.

#@load base/frameworks/packet-filter
#@load base/utils/addrs

module Broker;

export {

	## The communication logging stream identifier.
	#redef enum Log::ID += { LOG };

	## Which interface to listen on. The addresses ``0.0.0.0`` and ``[::]``
	## are wildcards.
	const listen_interface = 0.0.0.0 &redef;

	## Which port to listen on.  Note that BroControl sets this
	## automatically.
	const listen_port = 9999/tcp &redef;

	## This defines if a listening socket should use SSL.
	const listen_ssl = F &redef;

	## Defines if a listening socket can bind to IPv6 addresses.
	##
	## Note that this is overridden by the BroControl IPv6Comm option.
	const listen_ipv6 = F &redef;

	## If :bro:id:`Broker::listen_interface` is a non-global
	## IPv6 address and requires a specific :rfc:`4007` ``zone_id``,
	## it can be specified here.
	const listen_ipv6_zone_id = "" &redef;

	## Defines the interval at which to retry binding to
	## :bro:id:`Broker::listen_interface` on
	## :bro:id:`Broker::listen_port` if it's already in use.
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
		## Broker instances.
		message:             string &log;
	};

	## A remote peer to which we would like to talk.
	## If there's no entry for a peer, it may still connect
	## and request state, but not send us any.
	type Node: record {
		## Remote address.
		ip: addr;

		## If the *ip* field is a non-global IPv6 address, this field
		## can specify a particular :rfc:`4007` ``zone_id``.
		zone_id: string &optional;

		## Port of the remote Bro communication endpoint if we are
		## initiating the connection (based on the *connect* field).
		p: port &optional;

		## Whether we are going to connect (rather than waiting
		## for the other side to connect to us).
		connect: bool &default = F;

		## If disconnected, reconnect after this many seconds.
		retry: interval &default = 1 secs;

		## Whether to request logs from the peer.
		request_logs: bool &default = F;

		## If not set, no capture filter is sent.
		## If set to an empty string, then the default capture filter
		## is sent.
		# TODO still needed?
		capture_filter: string &optional;

		## Whether to use SSL-based communication.
		# TODO not supported by broker yet
		ssl: bool &default = F;

		## The remote peer.
		peer: string &optional;

		## Indicates the status of the node.
		connected: bool &default = F;

	};

	## The table of Bro or Broker nodes that Bro will initiate connections
	## to or respond to connections from.  Note that BroControl sets this
	## automatically.
	global nodes: table[string] of Node &redef;

	## A table of peer nodes for which this node issued a
	## :bro:id:`Broker::connect_peer` call but with which a connection
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

	## Data structure that keeps mappings between IP::port and the broker-name of peers 
	## TODO Currently this is a hack as broker should return the peer-name in call cases
	global peer_mapping: table[string] of string;

	## Connect to a node in :bro:id:`Broker::nodes` independent
	## of its "connect" flag.
	##
	## peer: the string used to index a particular node within the
	##      :bro:id:`Broker::nodes` table.
	global connect_peer: function(peer: string);

	global reconnect_interval: interval = 1 secs;

	## Event that signals that we have finished the connection setup to a remote peer
	global outgoing_connection_established_event: event(peer_name: string);
}

const src_names = {
	[REMOTE_SRC_CHILD]  = "child",
	[REMOTE_SRC_PARENT] = "parent",
	[REMOTE_SRC_SCRIPT] = "script",
};

function do_script_log_common(peer_name: string, level: count, src: count, msg: string)
	{
	#Log::write(Broker::LOG, [$ts = network_time(),
	#                                $level = (level == REMOTE_LOG_INFO ? "info" : "error"),
	#                                $src_name = src_names[src],
	#                                $peer = peer_name,
	#                                $message = msg]);
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

	node$p = p;

	# ...and connect via broker
	local succ = Broker::connect(fmt("%s", node$ip), p, node$retry);

	#if ( !succ )
	#	Log::write(Broker::LOG, [$ts = network_time(),
	#	                                $peer = peer,
	#	                                $message = "can't trigger connect"]);
	local id = fmt("%s:%s", node$ip, p);
	pending_peers[id] = node;
	}

function disconnect_peer(peer: string)
	{
	if( !(peer in connected_peers) )
		return;

	print "  - disconnect from peer ", peer, " with ip ", connected_peers[peer]$ip, " on port ", connected_peers[peer]$p;
	local node = connected_peers[peer];

	local saddr = fmt("%s", node$ip);
	local p = listen_port;
	# obtain port
	if ( node?$p )
		p = node$p;

	# ... and disconnect via broker
	local res = Broker::disconnect(saddr, p);
	delete connected_peers[peer];
	}

function setup_peer(peer_name: string, node: Node)
	{
	node$peer = peer_name;
	node$connected = T;
	nodes[peer_name] = node;
	connected_peers[peer_name] = node;
	}

event Cluster::node_updated(node_name: string)
	{
	# 1. disconnect from all peers we are not connected to anymore
	for ( tag in connected_peers )
		{
			if( !( tag in nodes ) )
				disconnect_peer(tag);
		}

	# 2. check all remaining peers if we might need to establish additional connections
	for ( tag in nodes )
		{
		print "check node ", tag , " with connect ", nodes[tag]$connect;
		if ( nodes[tag]$connect && !(tag in connected_peers) )
			connect_peer(tag);
		else if( !(nodes[tag]$connect) && tag in connected_peers && tag != "control" )
			disconnect_peer(tag);
		}
	}

event Broker::incoming_connection_established(peer_name: string)
	{
	do_script_log(Broker::endpoint_name, fmt("incoming connection established by %s", peer_name));
	if ( peer_name in nodes )
		{
		local node = nodes[peer_name];
		setup_peer(peer_name, node);
		}
	}

event Broker::incoming_connection_broken(peer_name: string)
	{
	do_script_log(Broker::endpoint_name, fmt("incoming connection broken to %s", peer_name));
	}

event Broker::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
	{
	local id = fmt("%s:%s", peer_address, peer_port);
	local node = pending_peers[id];
	delete pending_peers[id];

	do_script_log(Broker::endpoint_name, fmt("outgoing connection established to %s", peer_name));

	setup_peer(peer_name, node);
	peer_mapping[fmt("%s::%s", peer_address, peer_port)] = peer_name;

	event Broker::outgoing_connection_established_event(peer_name);
	}

event Broker::outgoing_connection_broken(peer_address: string, peer_port: port, peer_name: string)
	{
	# Retrieve the peer_name according to peer_address and peer_port
	for ( i in connected_peers )
		{
			local n = connected_peers[i];
			if ( fmt("%s", n$ip) == peer_address && n$p == peer_port )
				peer_name = i;
		}
	do_script_log(Broker::endpoint_name, fmt("connection closed/broken to %s", peer_name));

	if ( peer_name in connected_peers )
		{
		local node = connected_peers[peer_name];
		node$connected = F;
		delete connected_peers[peer_name];
	
		# Broker will retry.
		if ( reconnect_interval != 0secs )
			{
			local id = fmt("%s:%s", peer_address, peer_port);
			pending_peers[id] = nodes[peer_name];
			}
		}
	}

event Broker::outgoing_connection_incompatible(peer_address: string, peer_port: port)
	{
	do_script_log(peer_address, "outgoing connection incompatible");
	}

event bro_init() &priority=10
	{
	Broker::enable();
	}

event bro_init() &priority=5
	{
	#Log::create_stream(Broker::LOG, [$columns=Info, $path="broker"]);
	}

# Actually initiate the connections that need to be established.
event bro_init() &priority = -10 # let others modify nodes
	{
	for ( tag in nodes )
		{
		if ( ! nodes[tag]$connect )
			next;

		connect_peer(tag);
		}
	}
