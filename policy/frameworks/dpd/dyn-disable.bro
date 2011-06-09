##! When this script is loaded, analyzers that raise protocol_violation events
##! are disabled for the affected connection.

@load dpd/base
@load notice

module DPD;

export {
	redef enum Notice::Type += {
		ProtocolViolation
	};
	
	redef record DPD::Info += {
		## Disabled analyzer IDs.
		# TODO: This is waiting on ticket #460 to remove the '0'.
		disabled_aids: set[count] &default=set(0);
	};
	
	## Ignore violations which go this many bytes into the connection.
	const max_data_volume = 10 * 1024 &redef;
}


event protocol_violation(c: connection, atype: count, aid: count,
				reason: string) &priority=5
	{
	if ( aid in c$dpd$disabled_aids )
		return;

	local size = c$orig$size + c$resp$size;
	if ( max_data_volume > 0 && size > max_data_volume )
		return;

	# Disable the analyzer that raised the last core-generated event.
	disable_analyzer(c$id, aid);
	add c$dpd$disabled_aids[aid];

	NOTICE([$note=ProtocolViolation, $conn=c,
	        $msg=fmt("%s disabled due to protocol violation", analyzer_name(atype)),
	        $sub=reason, $n=atype]);
	}
