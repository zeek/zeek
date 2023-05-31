##! In a cluster configuration, open port 9911 on the manager for
##! Prometheus exposition and import all metrics from
##! `zeek/cluster/metrics/...` topic.
##!
##! For customization or disabling, redef the involved Broker options again.
##! Specifically, to disable listening on port 9911, set
##! :zeek:see:`Broker::metrics_port` to `0/unknown` again.

@load base/frameworks/cluster

# Use Cluster::node as "endpoint" label
redef Broker::metrics_export_endpoint_name = Cluster::node;

# The manager opens port 9911 and imports metrics from all nodes by default.
@if ( Cluster::local_node_type() == Cluster::MANAGER )
redef Broker::metrics_port = 9911/tcp;
redef Broker::metrics_import_topics = vector("zeek/cluster/metrics/");

@else
redef Broker::metrics_export_topic = "zeek/cluster/metrics/";
@endif
