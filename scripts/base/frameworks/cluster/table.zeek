##! Supporting code for &publish_on_change

module Cluster;

@load base/bif/publish_on_change.bif

# Event for processing change events from other nodes.
#
# If you need information about the sending node or additional information,
# that is not part of of the :zeek:see:`TableChangeInfo`, look into adding
# event metadata.
#
# id: The script layer identifier for the table, like "X509::known_log_certs"
# table_change_infos: Changes to a given table
event table_change_infos(id: string, ts: time, tcinfos: TableChangeInfos)
	{
	# Allow hooking the processing of table change infos. Could
	# consider replicating the changes to a separate system, etc.
	#
	# If an implementation breaks, nothing will happen.
	if ( ! hook apply_table_change_infos_policy(id, ts, tcinfos) )
		return;

	apply_table_change_infos(id, ts, tcinfos);

	# When running under Broker, the manager re-publishes the inserts
	# to workers if this is using the default topic.
	#
	# XXX: How do we figure this out?

	if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER && Cluster::local_node_type() == Cluster::MANAGER )
		Cluster::publish(Cluster::worker_topic, table_change_infos, id, tcinfos);
	}

# This event is used by workers when Broker is enabled because workers do not
# see each others events and full &publish_on_change functionality requires
# this to work. Workers delegate the publishing to the manager.
#
# XXX: Note that the manager raises table_change_infos() locally if it recognizes
#      ``to`` matching the Cluster::manager_topic or the zeek/table/ or its own
#      node or nodeid topics.
#
#      There will be a warning for ``to`` values that aren't recognized.
#
#      We could add redef'ble sets so that this so it can be fixed at configuration
#      time. But given this is Broker-specific, not sure its worth it.
event forward_table_change_infos(id: string, ts: time, tcinfos: TableChangeInfos, to: string)
	{
	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
		Reporter::fatal(fmt("forward_table_change_infos unexpected for %s", Cluster::backend));

	if ( Cluster::local_node_type() != Cluster::MANAGER )
		Reporter::fatal(fmt("%s got unexpected event forward_table_change_infos to=%s id=%s)", Cluster::node, to, id));

	Cluster::publish(to, table_change_infos, id, ts, tcinfos);

	local for_manager: bool =
		to == Cluster::manager_topic ||
		/^zeek\/table\// in to ||
		to == Cluster::node_topic("manager") ||
		to == Cluster::nodeid_topic("manager");

	local not_for_manager: bool =
		to == Cluster::proxy_topic ||
		to == Cluster::worker_topic ||
		starts_with(to, Cluster::node_topic_prefix) ||
		starts_with(to, Cluster::nodeid_topic_prefix);

	if ( for_manager )
		{
		event table_change_infos(id, ts, tcinfos);
		}
	else if ( not_for_manager )
		{
		# Nothing to do
		}
	else
		{
		Reporter::warning(fmt("Unhandled &publish_on_change forward_table_change_infos() topic to %s", to));
		}
	}

event zeek_init()
	{
	local topic_separator = "/";
	local topic = join_string_vec(vector("zeek", "table", ""), topic_separator);
	Cluster::subscribe(topic);

	# If Broker is enabled and this is a worker, send changes through the manager.
	if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER && Cluster::local_node_type() == Cluster::WORKER )
		set_forward_table_change_infos_topic(Cluster::manager_topic);
	}
