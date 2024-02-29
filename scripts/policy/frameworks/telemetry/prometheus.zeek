##! In a cluster configuration, open port 9911 on the manager for
##! Prometheus exposition and import all metrics from the
##! `zeek/cluster/metrics/...` topic.
##!
##! For customization or disabling, redef the involved Telemetry options
##! again. Specifically, to disable listening on port 9911, set
##! :zeek:see:`Telemetry::metrics_port` to `0/unknown` again.
##!
##! Note that in large clusters, metrics import may cause significant
##! communication overhead as well as load on the manager.
##!
@load base/frameworks/cluster

@if ( Cluster::is_enabled() )

# Use Cluster::node as "endpoint" label
redef Telemetry::metrics_export_endpoint_name = Cluster::node;

# The manager opens port 9911 and imports metrics from all nodes by default.
@if ( Cluster::local_node_type() == Cluster::MANAGER )
redef Telemetry::metrics_port = 9911/tcp;
redef Telemetry::metrics_import_topics = vector("zeek/cluster/metrics/");

@else
redef Telemetry::metrics_export_topic = "zeek/cluster/metrics/";
@endif

@endif
