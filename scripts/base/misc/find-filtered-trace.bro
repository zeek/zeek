##! Discovers trace files that contain TCP traffic consisting only of
##! control packets (e.g. it's been filtered to contain only SYN/FIN/RST
##! packets and no content).  On finding such a trace, a warning is
##! emitted that suggests toggling the :bro:see:`detect_filtered_trace`
##! option may be desired if the user does not want Bro to report
##! missing TCP segments.

module FilteredTraceDetection;

export {

	## Flag to enable filtered trace file detection and warning message.
	global enable: bool = T &redef;
}

global saw_tcp_conn_with_data: bool = F;
global saw_a_tcp_conn: bool = F;

event connection_state_remove(c: connection)
	{
	if ( ! reading_traces() )
		return;

	if ( ! enable )
		return;

	if ( saw_tcp_conn_with_data )
		return;

	if ( ! is_tcp_port(c$id$orig_p) )
		return;

	saw_a_tcp_conn = T;

	if ( /[Dd]/ in c$history )
		saw_tcp_conn_with_data = T;
	}

event bro_done()
	{
	if ( ! enable )
		return;

	if ( ! saw_a_tcp_conn )
		return;

	if ( ! saw_tcp_conn_with_data )
		Reporter::warning("The analyzed trace file was determined to contain only TCP control packets, which may indicate it's been pre-filtered.  By default, Bro reports the missing segments for this type of trace, but the 'detect_filtered_trace' option may be toggled if that's not desired.");
	}
