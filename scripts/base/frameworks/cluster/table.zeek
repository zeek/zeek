##! Supporting code for &publish_on_change

module Cluster::Table;

@load base/bif/cluster_table.bif

# Event for processing change events from other nodes.
#
# If you need the sending node or extra information, looking into
# event metadata.
#
# id: The script layer identifier for the table, like "X509::known_log_certs"
# table_change_infos: Changes to a given table
#
event table_change_infos_internal(id: string, table_change_infos: TableChangeInfos)
	{

	# Allow hooking the processing of table change infos. Could
	# consider replicating the changes to a separate system, etc.
	#
	# If an implementation breaks, nothing will happen.
	if ( ! hook apply_table_change_infos_policy(id, change_infos) )
		return;

	apply_table_change_infos(id, table_change_infos);

	# When running under Broker, the manager re-publishes the inserts
	# to workers if this is using the default topic.
	#
	# XXX: How do we figure this out?

	if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER && Cluster::local_node_type() == Cluster::MANAGER )
		Cluster::publish(Cluster::worker_topic, elements_new_internal, id, new_elements);
	}

event zeek_init()
	{
	local topic_separator = "/";
	local topic = join_string_vec(vector("zeek", "table", ""), topic_separator);
	Cluster::subscribe(topic);
	}
