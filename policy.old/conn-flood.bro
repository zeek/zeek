# $Id$
#
# Script which alarms if the number of connections per time interval
# exceeds a threshold.
#
# This script is mainly meant as a demonstration; it hasn't been hardened
# with/for operational use.

@load notice

module ConnFlood;

export {
	redef enum Notice += {
		ConnectionFloodStart, ConnectionFloodEnd,
	};

	# Thresholds to reports (conns/sec).
	const thresholds: set[count] =
		{ 1000, 2000, 4000, 6000, 8000, 10000, 20000, 50000 }
	&redef;

	# Average over this time interval.
	const avg_interval = 10 sec &redef;
}

global conn_counter = 0;
global last_thresh = 0;

# Note: replace with connection_attempt if too expensive.
event new_connection(c: connection)
	{
	++conn_counter;
	}

event check_flood()
	{
	local thresh = 0;
	local rate = double_to_count(interval_to_double((conn_counter / avg_interval)));

	# Find the largest threshold reached this interval.
	for ( i in thresholds )
		{
		if ( rate >= i && rate > thresh )
			thresh = i;
		}

	# Report if larger than last reported threshold.
	if ( thresh > last_thresh )
		{
		NOTICE([$note=ConnectionFloodStart, $n=thresh,
			   $msg=fmt("flood begins at rate %d conns/sec", rate)]);
		last_thresh = thresh;
		}

	# If no threshold was reached, the flood is over.
	else if ( thresh == 0 && last_thresh > 0 )
		{
		NOTICE([$note=ConnectionFloodEnd, $n=thresh,
			   $msg=fmt("flood ends at rate %d conns/sec", rate)]);
		last_thresh = 0;
		}

	conn_counter = 0;
	schedule avg_interval { check_flood() };
	}

event bro_init()
	{
	schedule avg_interval { check_flood() };
	}
