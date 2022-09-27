##! This script enables logging of packet segment data when a protocol
##! parsing violation is encountered.  The amount of data from the
##! packet logged is set by the :zeek:see:`DPD::packet_segment_size` variable.
##! A caveat to logging packet data is that in some cases, the packet may
##! not be the packet that actually caused the protocol violation.

module DPD;

export {
	redef record Info += {
		## A chunk of the payload that most likely resulted in the
		## analyzer violation.
		packet_segment: string &optional &log;
	};

	## Size of the packet segment to display in the DPD log.
	option packet_segment_size: int = 255;
}


event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo) &priority=4
	{
	if ( ! is_protocol_analyzer(atype) && ! is_packet_analyzer(atype) )
		return;

	if ( ! info?$c || ! info$c?$dpd )
		return;

	info$c$dpd$packet_segment = fmt("%s", sub_bytes(get_current_packet()$data, 0, packet_segment_size));
	}
