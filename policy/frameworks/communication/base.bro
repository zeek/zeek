##! Connect to remote Bro or Broccoli instances to share state and/or transfer
##! events.

@load packet-filter

module Communication;

export {
	redef enum Log::ID += { COMMUNICATION };
	
	const default_port_ssl = 47756/tcp &redef;
	const default_port_clear = 47757/tcp &redef;

	## Default compression level.  Compression level is 0-9, with 0 = no 
	## compression.
	global default_compression = 0 &redef;

	type Info: record {
		ts:           time &log;
		level:        string &log &optional;
		src_name:     string &log &optional;
		remote_node:  string &log &optional;
		message:      string &log;
	};

	## A remote peer to which we would like to talk.
	## If there's no entry for a peer, it may still connect
	## and request state, but not send us any.
	type Node: record {
		## Remote address.
		host: addr;
		
		## Port of the remote Bro communication endpoint if we are initiating
		## the connection based on the :bro:id:`connect` field.
		p: port &optional;

		## When accepting a connection, the configuration only
		## applies if the class matches the one transmitted by
		## the peer.
		##
		## When initiating a connection, the class is sent to
		## the other side.
		class: string &optional;

		## Events requested from remote side.
		events: pattern &optional;

		## Whether we are going to connect (rather than waiting
		## for the other sie to connect to us).
		connect: bool &default = F;

		## If disconnected, reconnect after this many seconds.
		retry: interval &default = 0 secs;

		## Whether to accept remote events.
		accept_input: bool &default = T;

		## Whether to perform state synchronization with peer.
		sync: bool &default = T;

		## Whether to request logs from the peer.
		request_logs: bool &default = F;

		## When performing state synchronization, whether we consider
		## our state to be authoritative.  If so, we will send the peer
		## our current set when the connection is set up.
		## (Only one side can be authoritative)
		auth: bool &default = F;

		## If not set, no capture filter is sent.
		## If set to "", the default cature filter is sent.
		capture_filter: string &optional;

		## Whether to use SSL-based communication.
		ssl: bool &default = F;

		## Take-over state from this host (activated by loading hand-over.bro)
		hand_over: bool &default = F;

		## Compression level is 0-9, with 0 = no compression.
		compression: count &default = default_compression;

		## The remote peer.
		peer: event_peer &optional;
		
		## Indicates the status of the node.
		connected: bool &default = F;
	};

	## The table of Bro or Broccoli nodes that Bro will initiate connections
	## to or respond to connections from.
	const nodes: table[string] of Node &redef;

	# Write log message into remote.log
	#global do_script_log: function(p: event_peer, msg: string);

	global pending_peers: table[peer_id] of Node;
	global connected_peers: table[peer_id] of Node;

	# Connect to nodes[node], independent of its "connect" flag.
	global connect_peer: function(peer: string);
}

const src_names = {
	[REMOTE_SRC_CHILD] = "[child] ",
	[REMOTE_SRC_PARENT] = "[parent]",
	[REMOTE_SRC_SCRIPT] = "[script]",
};

event bro_init()
	{
	Log::create_stream(COMMUNICATION, [$columns=Info]);
	}

function do_script_log_common(level: count, src: count, msg: string)
	{
	Log::write(COMMUNICATION, [$ts = network_time(), 
	                           $level = (level == REMOTE_LOG_INFO ? "[info] " : "[error]"),
	                           $src_name = src_names[src],
	                           $message = msg]);
	}

# This is a core generated event.
event remote_log(level: count, src: count, msg: string)
	{
	do_script_log_common(level, src, msg);
	}

function do_script_log(p: event_peer, msg: string)
	{
	do_script_log_common(REMOTE_LOG_INFO, REMOTE_SRC_SCRIPT,
				  fmt("[#%d/%s:%d] %s", p$id, p$host, p$p, msg));
	}

function connect_peer(peer: string)
	{
	local node = nodes[peer];
	local p = node$ssl ? default_port_ssl : default_port_clear;

	if ( node?$p )
		p = node$p;

	local class = node?$class ? node$class : "";
	local id = connect(node$host, p, class, node$retry, node$ssl);

	if ( id == PEER_ID_NONE )
		Log::write(COMMUNICATION, [$ts = network_time(), 
		                           $remote_node = fmt("%s:%d", node$host, p),
		                           $message = "can't trigger connect"]);
	pending_peers[id] = node;
	}


function setup_peer(p: event_peer, node: Node)
	{
	if ( node?$events )
		{
		do_script_log(p, fmt("requesting events matching %s", node$events));
		request_remote_events(p, node$events);
		}

	if ( node?$capture_filter )
		{
		local filter = node$capture_filter;
		if ( filter == "" )
			filter = PacketFilter::default_filter;

		do_script_log(p, fmt("sending capture_filter: %s", filter));
		send_capture_filter(p, filter);
		}

	if ( node$accept_input )
		{
		do_script_log(p, "accepting state");
		set_accept_state(p, T);
		}

	set_compression_level(p, node$compression);

	if ( node$sync )
		{
		do_script_log(p, "requesting synchronized state");
		request_remote_sync(p, node$auth);
		}

	if ( node$request_logs )
		{
		do_script_log(p, "requesting logs");
		request_remote_logs(p);
		}

	node$peer = p;
	node$connected = T;
	connected_peers[p$id] = node;
	}

event remote_connection_established(p: event_peer)
	{
	if ( is_remote_event() )
		return;

	do_script_log(p, "connection established");

	if ( p$id in pending_peers )
		{
		# We issued the connect.
		local node = pending_peers[p$id];
		setup_peer(p, node);
		delete pending_peers[p$id];
		}
	else
		{ # The other side connected to us.
		local found = F;
		for ( i in nodes )
			{
			node = nodes[i];
			if ( node$host == p$host )
				{
				local c = 0;

				# See if classes match = either both have
				# the same class, or neither of them has
				# a class.
				if ( p?$class && p$class != "" )
					++c;

				if ( node?$class && node$class != "" )
					++c;

				if ( c == 1 ||
				     (c == 2 && p$class != node$class) )
					next;

				found = T;
				setup_peer(p, node);
				break;
				}
			}

		if ( ! found )
			set_compression_level(p, default_compression);
		}

	complete_handshake(p);
	}

event remote_connection_closed(p: event_peer)
	{
	if ( is_remote_event() )
		return;

	do_script_log(p, "connection closed");

	if ( p$id in connected_peers )
		{
		local node = connected_peers[p$id];
		node$connected = F;

		delete connected_peers[p$id];

		if ( node$retry != 0secs )
			# The core will retry.
			pending_peers[p$id] = node;
		}
	}

event remote_state_inconsistency(operation: string, id: string,
				expected_old: string, real_old: string)
	{
	if ( is_remote_event() )
		return;

	local msg = fmt("state inconsistency: %s should be %s but is %s before %s",
	                id, expected_old, real_old, operation);
	Log::write(COMMUNICATION, [$ts = network_time(), 
	                           $message = msg]);
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
