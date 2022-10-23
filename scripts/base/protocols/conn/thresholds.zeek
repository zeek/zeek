##! Implements a generic API to throw events when a connection crosses a
##! fixed threshold of bytes or packets.

module ConnThreshold;

export {

	type Thresholds: record {
		orig_byte: set[count] &default=count_set(); ##< current originator byte thresholds we watch for
		resp_byte: set[count] &default=count_set(); ##< current responder byte thresholds we watch for
		orig_packet: set[count] &default=count_set(); ##< current originator packet thresholds we watch for
		resp_packet: set[count] &default=count_set(); ##< current responder packet thresholds we watch for
		duration: set[interval] &default=interval_set(); ##< current duration thresholds we watch for
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

	## Sets a duration threshold for a connection, adding it to potentially already existing thresholds.
	## conn_duration_threshold_crossed will be raised for each set threshold.
	##
	## cid: The connection id.
	##
	## threshold: Threshold in seconds.
	##
	## Returns: T on success, F on failure.
	global set_duration_threshold: function(c: connection, threshold: interval): bool;

	## Deletes a byte threshold for connection sizes.
	##
	## cid: The connection id.
	##
	## threshold: Threshold in bytes to remove.
	##
	## is_orig: If true, threshold is removed for packets from originator, otherwise for packets from responder.
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

	## Deletes a duration threshold for a connection.
	##
	## cid: The connection id.
	##
	## threshold: Threshold in packets.
	##
	## Returns: T on success, F on failure.
	global delete_duration_threshold: function(c: connection, threshold: interval): bool;

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

	## Generated for a connection that crossed a set duration threshold. Note that this event is
	## not raised at the exact moment that a duration threshold is crossed; instead it is raised
	## when the next packet is seen after the threshold has been crossed. On a connection that is
	## idle, this can be raised significantly later.
	##
	## c: the connection
	##
	## threshold: the threshold that was set
	##
	## is_orig: True if the threshold was crossed by the originator of the connection
	global duration_threshold_crossed: event(c: connection, threshold: interval, is_orig: bool);
}

redef record connection += {
	thresholds: ConnThreshold::Thresholds &optional;
};

type threshold_type: enum { BYTES, PACKETS, DURATION };

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

function find_min_duration_threshold(t: set[interval]): interval
	{
	if ( |t| == 0 )
		return 0secs;

	local first = T;
	local min: interval = 0 secs;

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

function set_current_threshold(c: connection, ttype: threshold_type, is_orig: bool): bool
	{
	local t: count = 0;
	local cur: count = 0;
	local td: interval = 0 secs;
	local curd: interval = 0 secs;

	if ( ttype == BYTES && is_orig )
		{
		t = find_min_threshold(c$thresholds$orig_byte);
		cur = get_current_conn_bytes_threshold(c$id, is_orig);
		}
	else if ( ttype == BYTES && ! is_orig )
		{
		t = find_min_threshold(c$thresholds$resp_byte);
		cur = get_current_conn_bytes_threshold(c$id, is_orig);
		}
	else if ( ttype == PACKETS && is_orig )
		{
		t = find_min_threshold(c$thresholds$orig_packet);
		cur = get_current_conn_packets_threshold(c$id, is_orig);
		}
	else if ( ttype == PACKETS && ! is_orig )
		{
		t = find_min_threshold(c$thresholds$resp_packet);
		cur = get_current_conn_packets_threshold(c$id, is_orig);
		}
	else if ( ttype == DURATION )
		{
		td = find_min_duration_threshold(c$thresholds$duration);
		curd = get_current_conn_duration_threshold(c$id);
		}

	if ( t == cur && td == curd )
		return T;

	if ( ttype == BYTES && is_orig )
		return set_current_conn_bytes_threshold(c$id, t, T);
	else if ( ttype == BYTES && ! is_orig )
		return set_current_conn_bytes_threshold(c$id, t, F);
	else if ( ttype == PACKETS && is_orig )
		return set_current_conn_packets_threshold(c$id, t, T);
	else if ( ttype == PACKETS && ! is_orig )
		return set_current_conn_packets_threshold(c$id, t, F);
	else # ttype == DURATION
		return set_current_conn_duration_threshold(c$id, td);
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

	return set_current_threshold(c, BYTES, is_orig);
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

	return set_current_threshold(c, PACKETS, is_orig);
	}

function set_duration_threshold(c: connection, threshold: interval): bool
	{
	set_conn(c);

	if ( threshold == 0 secs )
		return F;

	add c$thresholds$duration[threshold];

	return set_current_threshold(c, DURATION, T);
	}

function delete_bytes_threshold(c: connection, threshold: count, is_orig: bool): bool
	{
	set_conn(c);

	if ( is_orig && threshold in c$thresholds$orig_byte )
		{
		delete c$thresholds$orig_byte[threshold];
		set_current_threshold(c, BYTES, is_orig);
		return T;
		}
	else if ( ! is_orig && threshold in c$thresholds$resp_byte )
		{
		delete c$thresholds$resp_byte[threshold];
		set_current_threshold(c, BYTES, is_orig);
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
		set_current_threshold(c, PACKETS, is_orig);
		return T;
		}
	else if ( ! is_orig && threshold in c$thresholds$resp_packet )
		{
		delete c$thresholds$resp_packet[threshold];
		set_current_threshold(c, PACKETS, is_orig);
		return T;
		}

	return F;
	}

function delete_duration_threshold(c: connection, threshold: interval): bool
	{
	set_conn(c);

	if ( threshold in c$thresholds$duration )
		{
		delete c$thresholds$duration[threshold];
		set_current_threshold(c, DURATION, T);
		return T;
		}

	return F;
	}

event conn_bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool) &priority=5
	{
	if ( ! c?$thresholds )
		return;

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

	set_current_threshold(c, BYTES, is_orig);
	}

event conn_packets_threshold_crossed(c: connection, threshold: count, is_orig: bool) &priority=5
	{
	if ( ! c?$thresholds )
		return;

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

	set_current_threshold(c, PACKETS, is_orig);
	}

event conn_duration_threshold_crossed(c: connection, threshold: interval, is_orig: bool) &priority=5
	{
	if ( ! c?$thresholds )
		return;

	if ( threshold in c$thresholds$duration )
		{
		delete c$thresholds$duration[threshold];
		event ConnThreshold::duration_threshold_crossed(c, threshold, is_orig);
		}

	set_current_threshold(c, DURATION, is_orig);
	}
