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

redef Telemetry::metrics_endpoint_name = Cluster::node;

@if ( Cluster::local_node_metrics_port() != 0/unknown )
redef Telemetry::metrics_port = Cluster::local_node_metrics_port();
@endif

@endif
