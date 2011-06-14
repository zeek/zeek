@load metrics/base

redef enum Metrics::ID += { 
	CONNS_ORIGINATED, 
	CONNS_RESPONDED 
};

event bro_init()
	{
	Metrics::configure(CONNS_ORIGINATED, [$aggregation_mask=24, $break_interval=5mins]);
	Metrics::configure(CONNS_RESPONDED, [$aggregation_mask=24, $break_interval=5mins]);
	}

event connection_established(c: connection)
	{
	Metrics::add_data(CONNS_ORIGINATED, [$host=c$id$orig_h], 1);
	Metrics::add_data(CONNS_RESPONDED,  [$host=c$id$resp_h], 1);
	}
	