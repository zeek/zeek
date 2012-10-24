##! An example of using the metrics framework to collect connection metrics 
##! aggregated into /24 CIDR ranges.

@load base/frameworks/metrics
@load base/utils/site

redef enum Metrics::ID += { 
	CONNS_ORIGINATED, 
	CONNS_RESPONDED 
};

event bro_init()
	{
	Metrics::add_filter(CONNS_ORIGINATED, [$aggregation_mask=24, $break_interval=1mins]);
	
	# Site::local_nets must be defined in order for this to actually do anything.
	Metrics::add_filter(CONNS_RESPONDED,  [$aggregation_table=Site::local_nets_table, $break_interval=1mins]);
	}

event connection_established(c: connection)
	{
	Metrics::add_data(CONNS_ORIGINATED, [$host=c$id$orig_h], 1);
	Metrics::add_data(CONNS_RESPONDED,  [$host=c$id$resp_h], 1);
	}
	
