# $Id: cluster-manager.bro 6860 2009-08-14 19:01:47Z robin $
#
# Cluster manager configuration.

@prefixes += cluster-manager

@load broctl
@load filter-duplicates
@load notice
@load remote
@load rotate-logs
@load mail-alarms
	
# Since we don't capture, don't bother with this.
@unload print-filter

# Remote-print policy hooks into print() fucntion on remote hosts,
# and gets a copy to print to local files.
@load remote-print

# This grabs the remote peers (workers) and saves some status info
# to a local peer_status.log.
@load save-peer-status
	
# We have to listen of course... 
@load listen-clear
redef listen_port_clear = BroCtl::manager$p;

# The cluster manager does not capture.
redef interfaces = "";

# Give us a name. 
redef peer_description = BroCtl::manager$tag;

# Reraise remote notices locally.
event notice_action(n: notice_info, action: NoticeAction)
	{
	if ( is_remote_event() && FilterDuplicates::is_new(n) )
		NOTICE(n);
	}

redef FilterDuplicates::filters += {
	[Drop::AddressSeenAgain] = FilterDuplicates::match_src,
};
