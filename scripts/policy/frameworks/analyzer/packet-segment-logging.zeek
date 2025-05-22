##! This script enables logging of packet segment data when a protocol
##! parsing violation is encountered.  The amount of data from the
##! packet logged is set by the :zeek:see:`Analyzer::Logging::packet_segment_size` variable.
##! A caveat to logging packet data is that in some cases, the packet may
##! not be the packet that actually caused the protocol violation.

module Analyzer::Logging;

export {
	redef record connection += {
		## A chunk of the payload that most likely resulted in a
		## analyzer violation.
		packet_segment: string &optional &log;
	};

	redef record Analyzer::Logging::Info += {
		## A chunk of the payload that most likely resulted in the
		## analyzer violation.
		packet_segment: string &optional &log;
	};

	## Size of the packet segment to display in the DPD log.
	option packet_segment_size: int = 255;
}

# stash the packet segment in the event causing the violation, so that it can be retrieved later.
event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo) &priority=4
	{
	if ( ! is_protocol_analyzer(atype) && ! is_packet_analyzer(atype) )
		return;

	if ( ! info?$c || ! info?$aid )
		return;

	info$c$packet_segment = fmt("%s", get_current_packet()$data[:packet_segment_size]);
	}

hook Analyzer::Logging::log_policy(rec: Analyzer::Logging::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( id != Analyzer::Logging::LOG )
		return;

	if ( ! rec?$id || ! connection_exists(rec$id) )
		return;

	local c = lookup_connection(rec$id);

	if ( c?$packet_segment )
		rec$packet_segment = c$packet_segment;
	}
