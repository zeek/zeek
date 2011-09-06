##! This script adds the necessary environment variables for Bro to make use 
##! of PF_RING's clustering (and load balancing) support through the libpcap
##! wrapper.

module PFRing;

export {
	## Define the pf_ring cluster ID that you would like this instance
	## of Bro to use.  Please set a value from 0 to 255
	const cluster_id = 150 &redef;
}


event bro_init() &priority=10
	{
	if ( cluster_id > 255 || cluster_id < 0 )
		Reporter::fatal(fmt("%d is an invalid value for PFRing::cluster_id", cluster_id));
	
	if ( ! setenv("PCAP_PF_RING_USE_CLUSTER_PER_FLOW", "1") ||
	     ! setenv("PCAP_PF_RING_CLUSTER_ID", fmt("%d", cluster_id)) )
		Reporter::fatal("Unable to set one or both of the PF_RING environment variables.");
	}
