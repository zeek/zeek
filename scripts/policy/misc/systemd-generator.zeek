# Opinionated configuration for a cluster configured with the zeek-systemd-generator.

@load base/frameworks/cluster


# Ensure loggers rotate their log files into the spool/log-queue
# directory. This cannot really be changed right now, so hopefully
# that works.
#
# XXX: Does this allow <PREFIX>/spool to be on tmpfs?
@if ( Cluster::local_node_type() == Cluster::LOGGER || ! Cluster::is_enabled() )
@load base/frameworks/cluster/nodes/logger
@load base/frameworks/logging
redef Log::default_rotation_dir = "../log-queue";
redef Log::rotation_format_func = archiver_rotation_format_func;
redef LogAscii::enable_leftover_log_rotation = T;
redef Log::default_rotation_postprocessor_cmd = "";
@endif
