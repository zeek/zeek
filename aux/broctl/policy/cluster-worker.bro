# $Id: cluster-worker.bro 6811 2009-07-06 20:41:10Z robin $
#
# This is the cluster WORKER top-level policy for configuration settings that are 
# common to all worker node (as everything currently is except setting WORKER id).

@prefixes += cluster-worker

@load broctl
@load remote
@load rotate-logs

@load trim-trace-file	

@load analysis-groups
	
# Set up communications for updating workers.
@load listen-clear

redef listen_port_clear = BroCtl::workers[WORKER]$p;

# Give us a name.
redef peer_description = BroCtl::workers[WORKER]$tag;

# Don't do any local logging.
redef suppress_local_output = T;

# Record all packets into trace file.
redef record_all_packets = T;
