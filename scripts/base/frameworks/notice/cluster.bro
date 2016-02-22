##! Implements notice functionality across clusters.  Worker nodes
##! will disable notice/alarm logging streams and forward notice
##! events to the manager node for logging/processing.

@load ./main
@load base/frameworks/cluster

module Notice;

export {
	## This is the event used to transport notices on the cluster.
	##
	## n: The notice information to be sent to the cluster manager for
	##    further processing.
	global cluster_notice: event(n: Notice::Info);
}

## Manager can communicate notice suppression to workers.
redef Cluster::manager2worker_events += {"Notice::begin_suppression"};
## Workers need ability to forward notices to manager.
redef Cluster::worker2manager_events += {"Notice::cluster_notice"};

@if ( !(Cluster::has_local_role(Cluster::MANAGER)) )
event Notice::begin_suppression(n: Notice::Info)
	{
	local suppress_until = n$ts + n$suppress_for;
	suppressing[n$note, n$identifier] = suppress_until;
	}
@endif

@if ( Cluster::has_local_role(Cluster::MANAGER) )
event Notice::cluster_notice(n: Notice::Info)
	{
	# Raise remotely received notices on the manager
	NOTICE(n);
	}
@endif

module GLOBAL;

## This is the entry point in the global namespace for the notice framework.
function NOTICE(n: Notice::Info)
	{
	# Suppress this notice if necessary.
	if ( Notice::is_being_suppressed(n) )
		return;

	if ( Cluster::has_local_role(Cluster::MANAGER) )
		Notice::internal_NOTICE(n);
	else
		{
		n$peer_descr = peer_description;
		# For non-managers, send the notice on to the manager.
		event Notice::cluster_notice(n);
		}
	}
