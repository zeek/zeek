# $Id:$
#
# Sends the current value of an ID to a remote Bro and then terminates
# processing.
#
# Intended to be used from the command line as in:
#
# bro -e "redef Send::dst="<dst>" Send::id="<name-of-id>"
#		<other scripts> remote-send-id
#
# The other scripts must set up the connection.  <dst> is an index into
# Remote::destinations corresponding to the destination.

module Send;

@load remote

export {
	const dst = "<no-destination-given>" &redef;
	const id = "<no-id-given>" &redef;
}

event remote_connection_handshake_done(p: event_peer)
	{
	local peer = Remote::destinations[dst];

	if ( peer$host == p$host )
		{
		print fmt("Sending %s to %s at %s:%d", id, dst, p$host, p$p);
		send_id(p, id);
		terminate_communication();
		}
	}

event bro_init()
	{
	if ( dst !in Remote::destinations )
		{
		print fmt("Unknown destination %s", dst);
		terminate();
		return;
		}

	Remote::connect_peer(dst);
	}
