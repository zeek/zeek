##! Supporting code for &publish_on_change

module Cluster::Table;

@load base/bif/publish_on_change.bif

# Event for processing change events from other nodes.
#
# If you need information about the sending node or additional information,
# that is not part of of the :zeek:see:`TableChangeInfo`, look into adding
# event metadata.
#
# id: The script layer identifier for the table, like "X509::known_log_certs"
# table_change_infos: Changes to a given table
event table_change_infos_internal(id: string, ts: time, table_change_infos: TableChangeInfos) &is_used
	{
	# Allow hooking the processing of table change infos. Could
	# consider replicating the changes to a separate system, etc.
	#
	# If an implementation breaks, nothing will happen.
	if ( ! hook apply_table_change_infos_policy(id, ts, table_change_infos) )
		return;

	apply_table_change_infos(id, ts, table_change_infos);

	# When running under Broker, the manager re-publishes the inserts
	# to workers if this is using the default topic.
	#
	# XXX: How do we figure this out?

	if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER && Cluster::local_node_type() == Cluster::MANAGER )
		Cluster::publish(Cluster::worker_topic, table_change_infos_internal, id, table_change_infos);
	}

event zeek_init()
	{
	local topic_separator = "/";
	local topic = join_string_vec(vector("zeek", "table", ""), topic_separator);
	Cluster::subscribe(topic);
	}
