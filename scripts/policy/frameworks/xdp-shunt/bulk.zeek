##! Shunt large flows (aka elephant flows).

@ifdef ( XDP::__load_and_attach )

@load base/protocols/conn/thresholds

@load ./main
@load ./shunt_conn_id

module XDP::Shunt::Bulk;

export {
	## Number of bytes transferred before marking a connection as bulk.
	option size_threshold = 1048576; # 1MB
}

# Number of packets that need to be seen on a connection before engaging
# size monitoring. This is used to prevent introducing overhead for very
# short connections (e.g., DNS, scans).
const activation_packet_count = 10;
redef ConnThreshold::generic_packet_thresholds += {activation_packet_count};

event conn_generic_packet_threshold_crossed(c: connection, threshold: count)
	{
	if ( threshold != activation_packet_count )
		return;

	ConnThreshold::set_bytes_threshold(c, size_threshold, T);
	ConnThreshold::set_bytes_threshold(c, size_threshold, F);
	}

event ConnThreshold::bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool)
	{
	if ( threshold != size_threshold )
		return;

	XDP::Shunt::ConnID::shunt(c);
	}
@endif
