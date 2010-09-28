@load stepping

redef capture_filters += { ["ssh-stepping"] = "tcp port 22" };

module SSH_Stepping;

# Keeps track of how many connections each source is responsible for.
global ssh_src_cnt: table[addr] of count &default=0 &write_expire=15sec;

export {
	# Threshold above which we stop analyzing a source.
	# Use 0 to never stop.
	global src_fanout_no_stp_analysis_thresh = 100 &redef;
}

event connection_established(c: connection)
	{
	if ( c$id$resp_p == ssh )
		{
		# No point recording these, and they're potentially huge
		# due to use of ssh for file transfers.
		set_record_packets(c$id, F);

		# Keep track of sources that create lots of connections
		# so we can skip analyzing them - they're very likely
		# uninteresting for stepping stones, and can present
		# a large state burden.
		local src = c$id$orig_h;
		if ( ++ssh_src_cnt[src] == src_fanout_no_stp_analysis_thresh )
			add stp_skip_src[src];

		if ( ssh_src_cnt[src] == 1 )
			# First entry.  It's possible this entry was set
			# before and has now expired.  If so, stop skipping it.
			delete stp_skip_src[src];
		}
	}

event partial_connection(c: connection)
	{
	if ( c$id$orig_p == ssh || c$id$resp_p == ssh )
		# No point recording these, and they're potentially huge
		# due to use of ssh for file transfers.
		set_record_packets(c$id, F);
	}
