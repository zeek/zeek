# $Id: tm-capture.bro,v 1.1.2.1 2006/01/04 03:52:02 sommer Exp $
#
# For each non-scan alert, we can
#   (a) tell the time-machine to permanently store the connection's packets
#   (b) request the connection, to store the (reassembled) payload ourselves
#   (c) request all other traffic from that IP within the last X hours
#   (d) store all other traffic from that IP within the last X hours

@load time-machine
@load tm-contents
@load notice
@load scan

module TimeMachineCapture;

export {
	# Request past traffic. Set to 0 to disable.
	# This does on-disk queries, potentially expensive.
	const history_interval = 0 hrs &redef;

	# Capture past traffic. Set to 0 to disable.
	# This does on-disk queries, potentially expensive.
	const history_capture_interval = 0 hrs &redef;

	const ignore_notices: set[Notice] = {
		Scan::AddressScan,
		Scan::PortScan,
	} &redef;
}

@ifdef ( TimeMachineGap::ContentGapTmAndLink )
redef ignore_notices += {
	TimeMachineGap::ContentGapTmAndLink,
	TimeMachineGap::ContentGapSolved,
};
@endif

global hosts: set[addr] &create_expire = history_capture_interval;

global dbg = open_log_file("tm-capture");

event notice_alarm(n: notice_info, action: NoticeAction)
	{
	if ( n$note in ignore_notices )
		return;

	if ( ! n?$id )
		return;

	if ( n?$conn && is_external_connection(n$conn) )
		return;

	local id = n$id;
	local start: time;

	if ( n?$conn )
		start = n$conn$start_time;
	else if ( connection_exists(id) )
		start = lookup_connection(id)$start_time;
	else
		start = network_time() - 5 min;	# shouldn't usually get here

	local tag = fmt("conn.%s", n$tag);
	n$captured = tag;

	# It should be in the TM's memory.
	TimeMachine::capture_connection_id(fmt("%s.pcap", tag), id, start,
						T, "tm-capture");

	if ( get_port_transport_proto(id$resp_p) == tcp )
		{
		n$captured += " (contents)";
		TimeMachine::save_contents_id(tag, id, start, T, "tm-capture");
		}

	if ( n$src !in hosts )
		{
		if ( history_interval != 0 sec )
			TimeMachine::request_addr(n$src,
					network_time() - history_interval, F,
					"tm-capture");

		if ( history_capture_interval != 0secs )
			TimeMachine::capture_addr(fmt("host.%s.%s.pcap",
					n$src, n$tag), n$src,
					network_time() - history_capture_interval, F,
					"tm-capture");

		add hosts[n$src];
		}
	}
