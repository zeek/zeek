##! An example of using the metrics framework to collect connection metrics 
##! aggregated into /24 CIDR ranges.

@load base/frameworks/measurement
@load base/utils/site

event bro_init()
	{
	#Metrics::add_filter("conns.originated", [$aggregation_mask=24, $break_interval=1mins]);
	Metrics::add_filter("conns.originated", [$every=1mins, $measure=set(Metrics::SUM), 
	                                         $aggregation_table=Site::local_nets_table, 
	                                         $period_finished=Metrics::write_log]);
	
	
	# Site::local_nets must be defined in order for this to actually do anything.
	Metrics::add_filter("conns.responded",  [$every=1mins, $measure=set(Metrics::SUM),
	                                         $aggregation_table=Site::local_nets_table, 
	                                         $period_finished=Metrics::write_log]);

	}

event connection_established(c: connection)
	{
	Metrics::add_data("conns.originated", [$host=c$id$orig_h], [$num=1]);
	Metrics::add_data("conns.responded",  [$host=c$id$resp_h], [$num=1]);
	}
