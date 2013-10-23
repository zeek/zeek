##! This script enables logging of packet segment data when a protocol
##! parsing violation is encountered.  The amount of data from the
##! packet logged is set by the :bro:see:`DPD::packet_segment_size` variable.
##! A caveat to logging packet data is that in some cases, the packet may
##! not be the packet that actually caused the protocol violation.

@load base/frameworks/dpd

module DPD;

export {
	redef record Info += {
		## A chunk of the payload that most likely resulted in the
		## protocol violation.
		packet_segment: string &optional &log;
	};

	## Size of the packet segment to display in the DPD log.
	const packet_segment_size: int = 255 &redef;
}


event protocol_violation(c: connection, atype: Analyzer::Tag, aid: count,
                         reason: string) &priority=4
	{
	if ( ! c?$dpd ) return;
	
	c$dpd$packet_segment=fmt("%s", sub_bytes(get_current_packet()$data, 0, packet_segment_size));
	}
