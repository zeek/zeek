# The receiver of ping events locks itself up in the script layer after
# receiving a handful of pings from the sender. It does this lockup by sitting
# in a tight loop on sleeps, checking for the presence of a file after each
# sleep to break the loop, and hopefully resume receiving pings from the
# sender. Messaging to stdout provides status updates.

@load ./common.zeek

global epoch_rx = 0;
global pings_rx = 0;
global wedgie: event();

event wedgie()
	{
	# Loop forever, but check occasionally whether the unwedge_file exists,
	# and bail if so. Meanwhile pings coming in from the sender pile up.
	print fmt("%s wedging", current_time());

	while ( T )
		{
		sleep(1sec);

		if (file_size(unwedge_file) >= 0.0)
			{
			print fmt("%s unwedged", current_time());
			return;
			}
		}
	}

event ping(epoch: count, ctr: count, padding: string) &is_used
	{
	if ( epoch == 0 )
		{
		if ( ctr % 100 == 0 )
			print trace_file, fmt("%s ping %d in epoch %d", current_time(), ctr, epoch);

		# Lock up the script layer after we've received a few pings.
		# The pings continue to arrive but no longer make it to this
		# event handler, since we're busy-spinning above.
		if ( ++pings_rx == 10 )
			event wedgie();
		}

	if ( epoch == 1 && epoch_rx == 0 )
		{
		# We're starting to see pings again post-wedgie. W00t.
		print fmt("%s recovered", current_time());
		print trace_file, fmt("%s ping %d in epoch %d", current_time(), ctr, epoch);

		Cluster::publish(Cluster::manager_topic, terminate_me);
		Cluster::publish(termination_topic, terminate_me);
		event terminate_me();
		}

	epoch_rx = epoch;
	}
