# Notifications for Broker-reported backpressure overflow.
# See base/frameworks/broker/backpressure.zeek for context.

@load base/frameworks/telemetry

module Cluster;

global broker_backpressure_disconnects_cf = Telemetry::register_counter_family(Telemetry::MetricOpts(
    $prefix="zeek",
    $name="broker-backpressure-disconnects",
    $unit="",
    $label_names=vector("peer"),
    $help_text="Number of Broker peerings dropped due to a neighbor falling behind in message I/O",
));

event Broker::peer_removed(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( ! endpoint?$network || "caf::sec::backpressure_overflow" !in msg )
		return;

	local nn = nodeid_to_node(endpoint$id);

	Cluster::log(fmt("removed due to backpressure overflow: %s%s:%s (%s)",
	                 nn$name != "" ? "" : "non-cluster peer ",
	                 endpoint$network$address, endpoint$network$bound_port,
	                 nn$name != "" ? nn$name : endpoint$id));
	Telemetry::counter_family_inc(broker_backpressure_disconnects_cf,
	                              vector(nn$name != "" ? nn$name : "unknown"));
	}
