# $Id: drop-adapt.bro 6940 2009-11-14 00:38:53Z robin $
#
# Adjust load level based on packet drops.
#

@load load-level

# Increase load-level if packet drops are successively 'count' times
# above 'threshold' percent.
const drop_increase_count = 5 &redef;
const drop_increase_threshold = 5.0 &redef;

# Same for decreasing load-level.
const drop_decrease_count = 15 &redef;
const drop_decrease_threshold = 0.0 &redef;

# Minimum time to wait after a load-level increase before new decrease.
const drop_decrease_wait = 20 mins &redef;

global drop_last_stat: net_stats;
global drop_have_stats = F;
global drop_above = 0;
global drop_below = 0;

global drop_last_increase: time = 0;

event net_stats_update(t: time, ns: net_stats)
	{
	if ( drop_have_stats )
		{
		local new_recvd = ns$pkts_recvd - drop_last_stat$pkts_recvd;
		local new_dropped =
			ns$pkts_dropped - drop_last_stat$pkts_dropped;

		local p = new_dropped * 100.0 / new_recvd;

		drop_last_stat = ns;

		if ( p >= 0 )
			{
			if ( p >= drop_increase_threshold )
				{
				if ( ++drop_above >= drop_increase_count )
					{
					increase_load_level();
					drop_above = 0;
					drop_last_increase = t;
					}
				}
			else
				drop_above = 0;

			if ( t - drop_last_increase < drop_decrease_wait )
				return;

			if ( p <= drop_decrease_threshold )
				{
				if ( ++drop_below >= drop_decrease_count )
					{
					decrease_load_level();
					drop_below = 0;
					}
				}
			else
				drop_below = 0;

			}
		}
	else
		{
		drop_have_stats = T;
		drop_last_stat = ns;
		}
	}
