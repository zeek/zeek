# $Id:$
#
# Requests the current value of a variable (identifier) from a remote
# peer, prints it, and then terminates. The other side must load
# remote-print-id-reply.bro.
#
# Intended to be used from the command line as in:
#
# bro -e 'redef PrintID::dst="<dst>" PrintID::id="<name-of-id>"'
#		<other scripts> remote-print-id
#
# The other scripts must set up the connection.  <dst> is an index into
# Remote::destinations corresponding to the destination.

module PrintID;

@load remote
@load remote-print-id-reply

export {
	const dst = "<no-destination-given>" &redef;
	const id = "<no-id-given>" &redef;
}

event remote_connection_handshake_done(p: event_peer)
	{
	local peer = Remote::destinations[dst];

	if ( peer$host == p$host )
		{
		print fmt("Requesting %s from %s at %s:%d",
				id, dst, p$host, p$p);
		event request_id(id);
		}
	}

event request_id_response(id: string, content: string)
	{
	print fmt("%s = %s", id, content);
	terminate_communication();
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
