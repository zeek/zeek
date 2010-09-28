# $Id: tm-gap.bro,v 1.1.2.1 2006/01/05 22:38:37 sommer Exp $
#
# When we see a content gap, we request the same connection from the TM.
# If we get it from there completely, fine.  If not, we check whether the
# gap is at the same place as before, which would indicate that the packet
# was indeed missing on the link.

@load conn-id
@load time-machine

module TimeMachineGap;

export {
	# If true, we assume a BPF filter that includes *all* data packets.
	const seeing_all_packets = F &redef;

	# Exclude these ports.
	const ignore_ports = { 80/tcp, 22/tcp, 443/tcp };

	redef enum Notice += {
		# A connection has at least one gap that matches a gap
		# on the link.
		ContentGapTmAndLink,

		# A connection that had a gap on the link has been fully
		# received from the TM.
		ContentGapSolved,
	};
}

type gap : record {
	is_orig: bool;
	seq: count;
	length: count;
};

# Remembers the first gap per connection.
# (FIXME: Would it make sense to remember all gaps?)
global conns: table[conn_id] of gap;

global f = open_log_file("gap");

event content_gap(c: connection, is_orig: bool, seq: count, length: count)
	{
	if ( ! is_external_connection(c) )
		{
		if ( c$id in conns )
			# We already requested the conn.
			return;

		if ( c$id$resp_p in ignore_ports )
			return;

		# It only makes sense to request the connection if we are
		# not just analyzing TCP control packets for it.  There's
		# no perfect way to determine whether we do so but, as a
		# heuristic, we assume that we are supposed to see data
		# packets if:
		#
		# (1) the service port is well-known for one of our analyzers
		#     (because then the analyzer script is loaded which extends
		#     the capture filter accordingly; or
		# (2) the user explicitly tells us they are using a filter that
		#     includes all packets (e.g., DPD); or
		# (3) (special case) it's an HTTP reply, but we only
		#     load http-request.

		if ( ! seeing_all_packets )
			{
			if ( c$id$resp_p !in dpd_analyzer_ports )
				return;

			if ( c$id$resp_p in dpd_analyzer_ports && ! is_orig &&
			     ANALYZER_HTTP in dpd_analyzer_ports[c$id$resp_p])
				{
@ifdef ( process_HTTP_replies )
				if ( ! process_HTTP_replies )
@endif
				return;
				}
			}

		local g: gap = [$is_orig=is_orig, $seq=seq, $length=length];
		conns[c$id] = g;

		# Should be in TM's memory.
		TimeMachine::request_connection(c, T, "tm-gap");

		print f, "ask", id_string(c$id);
		}

	else
		{ # a gap in a connection from the TM
		if ( c$id !in conns )
			# Will be reported as ContentGap by weird.bro.
			return;

		local h = conns[c$id];

		if ( h$is_orig == is_orig && h$seq == seq && h$length == length )
			{
			NOTICE([$note=ContentGapTmAndLink, $conn=c,
				$msg=fmt("%s same content gap on link and from time-machine (%s %d/%d)",
					 id_string(c$id),
					 is_orig ? ">" : "<", seq, length)]);
			}

		delete conns[c$id];
		}
	}

event connection_external(c: connection, tag: string)
	{
	if ( c$id in conns )
		print f, "got", id_string(c$id);
	}

event connection_state_remove(c: connection)
	{
	if ( c$id in conns && is_external_connection(c) )
		{ # It's still in the table, so we got it completely. Yippie!
		NOTICE([$note=ContentGapSolved, $conn=c,
			$msg=fmt("%s content gap(s) solved by time-machine",
					id_string(c$id))]);
		delete conns[c$id];
		}
	}
