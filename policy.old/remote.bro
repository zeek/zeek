# $Id: remote.bro 5101 2007-11-29 07:02:27Z vern $
#
# Connect to remote Bros and request some of their events.

module Remote;

export {
	const default_port_ssl = 47756/tcp &redef;
	const default_port_clear = 47757/tcp &redef;

	# Default compression level.
	global default_compression = 0 &redef;

	# A remote peer to which we would like to talk.
	# If there's no entry for a peer, it may still connect
	# and request state, but not send us any.
	type Destination : record {
		# Destination endpoint.
		host: addr;
		p: port &optional;

		# When accepting a connection, the configuration only
		# applies if the class matches the one transmitted by
		# the peer.
		#
		# When initiating a connection, the class is sent to
		# the other side.
		class: string &optional;

		# Events requested from remote side.
		events: pattern &optional;

		# Whether we are going to connect (rather than waiting
		# for the other sie to connect to us).
		connect: bool &default = F;

		# If disconnected, reconnect after this many seconds.
		retry: interval &default = 0 secs;

		# Whether to accept remote events.
		accept_input: bool &default = T;

		# Whether to perform state synchronization with peer.
		sync: bool &default = T;

		# When performing state synchronization, whether we consider
		# our state to be authoritative.  If so, we will send the peer
		# our current set when the connection is set up.
		# (Only one side can be authoritative.)
		auth: bool &default = F;

		# If not set, no capture filter is sent.
		# If set to "", the default cature filter is sent.
		capture_filter: string &optional;

		# Whether to use SSL-based communication.
		ssl: bool &default = F;

		# Take-over state from this host
		# (activated by loading hand-over.bro)
		hand_over: bool &default = F;

		# Compression level is 0-9, with 0 = no compression.
		compression: count &default = default_compression;

		# Set when connected.
		peer: event_peer &optional;
		connected: bool &default = F;
	};

	const destinations: table[string] of Destination &redef;

	# redef destinations += {
	#	["foo"] = [$host = foo.bar.com, $events = /.*/, $connect=T, $retry = 60 secs, $ssl=T]
	# };

	# Write log message into remote.log
	global do_script_log: function(p: event_peer, msg: string);

	global pending_peers: table[peer_id] of Destination;
	global connected_peers: table[peer_id] of Destination;

	# Connect to destionations[dst], independent of its "connect" flag.
	global connect_peer: function(peer: string);
}

# Called rm_log rather than remote_log because there's an event by that name.
global rm_log = open_log_file("remote");

global src_names = {
	[REMOTE_SRC_CHILD] = "[child] ",
	[REMOTE_SRC_PARENT] = "[parent]",
	[REMOTE_SRC_SCRIPT] = "[script]",
};

function do_script_log_common(level: count, src: count, msg: string)
	{
	print rm_log,
		fmt("%.6f %s %s %s", current_time(),
			(level == REMOTE_LOG_INFO ? "[info] " : "[error]"),
			src_names[src], msg);
	}

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
	local dst = destinations[peer];
	local p = dst$ssl ? default_port_ssl : default_port_clear;

	if ( dst?$p )
		p = dst$p;

	local class = dst?$class ? dst$class : "";
	local id = connect(dst$host, p, class ,dst$retry, dst$ssl);

	if ( id == PEER_ID_NONE )
		print rm_log,
		fmt("%.6f %s/%d can't trigger connect",
			current_time(), dst$host, p);

	pending_peers[id] = dst;
	}

event bro_init() &priority = -10	# let others modify destinations
	{
	set_buf(rm_log, F);

	for ( tag in destinations )
		{
		if ( ! destinations[tag]$connect )
			next;

		connect_peer(tag);
		}
	}

function setup_peer(p: event_peer, dst: Destination)
	{
	if ( dst?$events )
		{
		do_script_log(p, fmt("requesting events matching %s", dst$events));
		request_remote_events(p, dst$events);
		}

	if ( dst?$capture_filter )
		{
		local filter = dst$capture_filter;
		if ( filter == "" )
			filter = default_pcap_filter;

		do_script_log(p, fmt("sending capture_filter: %s", filter));
		send_capture_filter(p, filter);
		}

	if ( dst$accept_input )
		{
		do_script_log(p, "accepting state");
		set_accept_state(p, T);
		}

	set_compression_level(p, dst$compression);

	if ( dst$sync )
		{
		do_script_log(p, "requesting synchronized state");
		request_remote_sync(p, dst$auth);
		}

	dst$peer = p;
	dst$connected = T;
	connected_peers[p$id] = dst;
	}

event remote_connection_established(p: event_peer)
	{
	if ( is_remote_event() )
		return;

	do_script_log(p, "connection established");

	if ( p$id in pending_peers )
		{
		# We issued the connect.
		local dst = pending_peers[p$id];
		setup_peer(p, dst);
		delete pending_peers[p$id];
		}
	else
		{ # The other side connected to us.
		local found = F;
		for ( i in destinations )
			{
			dst = destinations[i];
			if ( dst$host == p$host )
				{
				local c = 0;

				# See if classes match = either both have
				# the same class, or neither of them has
				# a class.
				if ( p?$class && p$class != "" )
					++c;

				if ( dst?$class && dst$class != "" )
					++c;

				if ( c == 1 ||
				     (c == 2 && p$class != dst$class) )
					next;

				found = T;
				setup_peer(p, dst);
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
		local dst = connected_peers[p$id];
		dst$connected = F;

		delete connected_peers[p$id];

		if ( dst$retry != 0secs )
			# The core will retry.
			pending_peers[p$id] = dst;
		}
	}

event remote_state_inconsistency(operation: string, id: string,
				expected_old: string, real_old: string)
	{
	if ( is_remote_event() )
		return;

	print rm_log,
		fmt("%.6f state inconsistency: %s should be %s but is %s before %s",
			network_time(), id, expected_old, real_old, operation);
	}
