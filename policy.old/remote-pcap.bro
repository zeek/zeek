# $Id: remote-pcap.bro 2704 2006-04-04 07:35:46Z vern $
#
# Allows remote peers to set our capture filter.

@load remote

# We install a filter which (hopefully) doesn't match anything to avoid Bro's
# default "tcp or udp" when no other script/peers adds a filter.

## FIXME: We need non-blocking pacp for this to work.
##
## ##redef capture_filters["match-nothing"] = "ether src 0:0:0:0:0:0";

function build_capture_filter_index(p: event_peer): string
	{
	return fmt("remote-%d", p$id);
	}

event remote_capture_filter(p: event_peer, filter: string)
	{
	# If we send a capture filter to a peer and are subscribed to all
	# of its events, we will get a remote_capture_filter event back.
	if ( is_remote_event() )
		return;

	Remote::do_script_log(p, fmt("received capture filter: %s", filter));

	capture_filters[build_capture_filter_index(p)] = filter;

	# This will recompile the filter, which may take some time.
	# Thus, setting a new capture_filter may cost us some packets :-(.
	update_default_pcap_filter();

	Remote::do_script_log(p, fmt("new default pcap filter: %s",
					default_pcap_filter));
	}

event remote_connection_closed(p: event_peer)
	{
	local i = build_capture_filter_index(p);

	if ( i in capture_filters )
		{
		Remote::do_script_log(p, fmt("removed capture filter: %s",
					capture_filters[i]));
		delete capture_filters[i];
		update_default_pcap_filter();
		}

	Remote::do_script_log(p, fmt("new default pcap filter: %s",
				default_pcap_filter));
	}
