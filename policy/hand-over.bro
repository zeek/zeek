# $Id: hand-over.bro 617 2004-11-02 00:54:31Z scottc $
#
# Hand-over between two instances of Bro.

@load remote

# The host from which we want to take over the state has to be
# added to remote_peers_{clear,ssl}, setting hand_over to T.
#
# The host which we want to allow to perform a hand-over with us
# has to be added to remote_peers with a port of 0/tcp and
# hand_over = T.

function is_it_us(host: addr, p: port): bool
	{
@ifdef ( listen_if_clear )
	if ( is_local_interface(host) && p == listen_port_clear )
		return T;
@endif

@ifdef ( listen_if_ssl )
	if ( is_local_interface(host) && p == listen_port_ssl )
	    return T;
@endif
	return F;
	}

function is_handover_peer(p: event_peer): bool
	{
	local peer: Remote::Destination;

	if ( p$id in Remote::pending_peers )
		peer = Remote::pending_peers[p$id];
	else
		return F;

	return peer$hand_over;
	}

function handover_start_processing()
	{
	uninstall_src_net_filter(0.0.0.0/0);
	}

event bro_init()
	{
	# Disable packet processing.
	install_src_net_filter(0.0.0.0/0, 0, 100);
	alarm "waiting for hand-over - packet processing disabled.";
	}

event remote_connection_error(p: event_peer, reason: string)
	{
	if ( is_remote_event() || ! ( p$id in Remote::connected_peers) )
		return;

	# Seems that the other side in not running.
	alarm "can't connect for hand-over - starting processing ...";
	handover_start_processing();
	}

event remote_connection_established(p: event_peer)
	{
	if ( is_remote_event() )
		return;

	# If [p$id] is defined in Remote::connected_peers and p != 0, we have connected
	# to the host.
	if ( p$p != 0/tcp &&
	     ([p$id] in Remote::connected_peers ) )
		{
		if ( ! is_handover_peer(p) )
			return;

		alarm fmt("requesting hand-over from %s:%d", p$host, p$p);

		request_remote_events(p, /handover_.*|finished_send_state/);

		# Give the remote side some time to register its handlers.
		schedule 3 secs { handover_request(p$host, p$p) };
		return;
		}

	# If the other side connected to us, we will allow the hand-over
	# if the remote host is defined as a hand-over host in remote_peers.
	if ( is_handover_peer(p) )
		{
		alarm fmt("allowing hand-over from %s:%d", p$host, p$p);
		request_remote_events(p, /handover_.*|finished_send_state/);
		}
	}

event handover_send_state(p: event_peer)
	{
	if ( is_remote_event() )
		return;

	# There may be a serialization in progress in which case
	# we will have to try again.
	if ( ! send_state(p) )
		{
		alarm "can't send state; serialization in progress";
		schedule 5 secs { handover_send_state(p$host, p$p) };
		}
	}

event handover_request(p: event_peer)
	{
	# Make sure the event is for us.
	if ( ! (is_remote_event() && is_it_us(p$host, p$p)) )
		return;

	# Send state to other side.
	schedule 1 sec { handover_send_state(p) };
	}

event finished_send_state(p: event_peer)
	{
	# We will get this event from the remote side.
	# Make sure it's indeed for us.
	if ( ! is_remote_event() )
		 return;

	if ( ! is_handover_peer(p) )
		 return;

	alarm fmt("full state received from %s:%d - starting processing ...",
		p$host, p$p);

	event handover_got_state(p);

	# Start processing.
	handover_start_processing();
	}

event handover_got_state(p: event_peer)
	{
	# Make sure the event is for us.
	if ( ! (is_remote_event() && is_it_us(p$host, p$p)) )
		return;

	alarm fmt("%s:%d received our state - terminating", p$host, p$p);
	terminate();
	}
