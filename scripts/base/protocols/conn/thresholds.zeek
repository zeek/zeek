##! Implements a generic API to throw events when a connection crosses a
##! fixed threshold of bytes or packets.

module ConnThreshold;

export {

	type Thresholds: record {
		orig_byte: set[count] &default=count_set(); ##< current originator byte thresholds we watch for
		resp_byte: set[count] &default=count_set(); ##< current responder byte thresholds we watch for
		orig_packet: set[count] &default=count_set(); ##< corrent originator packet thresholds we watch for
		resp_packet: set[count] &default=count_set(); ##< corrent responder packet thresholds we watch for
	};

	## Sets a byte threshold for connection sizes, adding it to potentially already existing thresholds.
	## conn_bytes_threshold_crossed will be raised for each set threshold.
	##
	## cid: The connection id.
	##
	## threshold: Threshold in bytes.
	##
	## is_orig: If true, threshold is set for bytes from originator, otherwise for bytes from responder.
	##
	## Returns: T on success, F on failure.
	global set_bytes_threshold: function(c: connection, threshold: count, is_orig: bool): bool;

	## Sets a packet threshold for connection sizes, adding it to potentially already existing thresholds.
	## conn_packets_threshold_crossed will be raised for each set threshold.
	##
	## cid: The connection id.
	##
	## threshold: Threshold in packets.
	##
	## is_orig: If true, threshold is set for packets from originator, otherwise for packets from responder.
	##
	## Returns: T on success, F on failure.
	global set_packets_threshold: function(c: connection, threshold: count, is_orig: bool): bool;

	## Deletes a byte threshold for connection sizes.
	##
	## cid: The connection id.
	##
	## threshold: Threshold in bytes to remove.
	##
	## is_orig: If true, threshold is removed for packets from originator, otherwhise for packets from responder.
	##
	## Returns: T on success, F on failure.
	global delete_bytes_threshold: function(c: connection, threshold: count, is_orig: bool): bool;

	## Deletes a packet threshold for connection sizes.
	##
	## cid: The connection id.
	##
	## threshold: Threshold in packets.
	##
	## is_orig: If true, threshold is removed for packets from originator, otherwise for packets from responder.
	##
	## Returns: T on success, F on failure.
	global delete_packets_threshold: function(c: connection, threshold: count, is_orig: bool): bool;

	## Generated for a connection that crossed a set byte threshold
	##
	## c: the connection
	##
	## threshold: the threshold that was set
	##
	## is_orig: True if the threshold was crossed by the originator of the connection
	global bytes_threshold_crossed: event(c: connection, threshold: count, is_orig: bool);

	## Generated for a connection that crossed a set byte threshold
	##
	## c: the connection
	##
	## threshold: the threshold that was set
	##
	## is_orig: True if the threshold was crossed by the originator of the connection
	global packets_threshold_crossed: event(c: connection, threshold: count, is_orig: bool);
}

redef record connection += {
	thresholds: ConnThreshold::Thresholds &optional;
};

function set_conn(c: connection)
	{
	if ( c?$thresholds )
		return;

	c$thresholds = Thresholds();
	}

function find_min_threshold(t: set[count]): count
	{
	if ( |t| == 0 )
		return 0;

	local first = T;
	local min: count = 0;

	for ( i in t )
		{
		if ( first )
			{
			min = i;
			first = F;
			}
		else
			{
			if ( i < min )
				min = i;
			}
		}

	return min;
	}

function set_current_threshold(c: connection, bytes: bool, is_orig: bool): bool
	{
	local t: count = 0;
	local cur: count = 0;

	if ( bytes && is_orig )
		{
		t = find_min_threshold(c$thresholds$orig_byte);
		cur = get_current_conn_bytes_threshold(c$id, is_orig);
		}
	else if ( bytes && ! is_orig )
		{
		t = find_min_threshold(c$thresholds$resp_byte);
		cur = get_current_conn_bytes_threshold(c$id, is_orig);
		}
	else if ( ! bytes && is_orig )
		{
		t = find_min_threshold(c$thresholds$orig_packet);
		cur = get_current_conn_packets_threshold(c$id, is_orig);
		}
	else if ( ! bytes && ! is_orig )
		{
		t = find_min_threshold(c$thresholds$resp_packet);
		cur = get_current_conn_packets_threshold(c$id, is_orig);
		}

	if ( t == cur )
		return T;

	if ( bytes && is_orig )
		return set_current_conn_bytes_threshold(c$id, t, T);
	else if ( bytes && ! is_orig )
		return set_current_conn_bytes_threshold(c$id, t, F);
	else if ( ! bytes && is_orig )
		return set_current_conn_packets_threshold(c$id, t, T);
	else if ( ! bytes && ! is_orig )
		return set_current_conn_packets_threshold(c$id, t, F);
	}

function set_bytes_threshold(c: connection, threshold: count, is_orig: bool): bool
	{
	set_conn(c);

	if ( threshold == 0 )
		return F;

	if ( is_orig )
		add c$thresholds$orig_byte[threshold];
	else
		add c$thresholds$resp_byte[threshold];

	return set_current_threshold(c, T, is_orig);
	}

function set_packets_threshold(c: connection, threshold: count, is_orig: bool): bool
	{
	set_conn(c);

	if ( threshold == 0 )
		return F;

	if ( is_orig )
		add c$thresholds$orig_packet[threshold];
	else
		add c$thresholds$resp_packet[threshold];

	return set_current_threshold(c, F, is_orig);
	}

function delete_bytes_threshold(c: connection, threshold: count, is_orig: bool): bool
	{
	set_conn(c);

	if ( is_orig && threshold in c$thresholds$orig_byte )
		{
		delete c$thresholds$orig_byte[threshold];
		set_current_threshold(c, T, is_orig);
		return T;
		}
	else if ( ! is_orig && threshold in c$thresholds$resp_byte )
		{
		delete c$thresholds$resp_byte[threshold];
		set_current_threshold(c, T, is_orig);
		return T;
		}

	return F;
	}

function delete_packets_threshold(c: connection, threshold: count, is_orig: bool): bool
	{
	set_conn(c);

	if ( is_orig && threshold in c$thresholds$orig_packet )
		{
		delete c$thresholds$orig_packet[threshold];
		set_current_threshold(c, F, is_orig);
		return T;
		}
	else if ( ! is_orig && threshold in c$thresholds$resp_packet )
		{
		delete c$thresholds$resp_packet[threshold];
		set_current_threshold(c, F, is_orig);
		return T;
		}

	return F;
	}

event conn_bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool) &priority=5
	{
	if ( is_orig && threshold in c$thresholds$orig_byte )
		{
		delete c$thresholds$orig_byte[threshold];
		event ConnThreshold::bytes_threshold_crossed(c, threshold, is_orig);
		}
	else if ( ! is_orig && threshold in c$thresholds$resp_byte )
		{
		delete c$thresholds$resp_byte[threshold];
		event ConnThreshold::bytes_threshold_crossed(c, threshold, is_orig);
		}

	set_current_threshold(c, T, is_orig);
	}

event conn_packets_threshold_crossed(c: connection, threshold: count, is_orig: bool) &priority=5
	{
	if ( is_orig && threshold in c$thresholds$orig_packet )
		{
		delete c$thresholds$orig_packet[threshold];
		event ConnThreshold::packets_threshold_crossed(c, threshold, is_orig);
		}
	else if ( ! is_orig && threshold in c$thresholds$resp_packet )
		{
		delete c$thresholds$resp_packet[threshold];
		event ConnThreshold::packets_threshold_crossed(c, threshold, is_orig);
		}

	set_current_threshold(c, F, is_orig);
	}
