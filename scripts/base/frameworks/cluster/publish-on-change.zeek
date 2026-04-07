##! Supporting script code for the &publish_on_change attribute.

module Cluster;

export {

	## Default number of :zeek:see:`Cluster::TableChangeInfo` records to use
	## with :zeek:see:`Cluster::publish_table`.
	const default_publish_table_batch_size = 10000 &redef;

	## Publish the given table_val using multiple :zeek:see:`Cluster::table_change_infos`
	## event to the given topic.
	##
	## topic: The topic to publish the :zeek:see:`Cluster::table_change_infos` event to.
	##        Usually this is created with :zeek:see:`Cluster::node_topic` or
	##        :zeek:see:`Cluster::nodeid_topic`.
	## table_val: The table to publish. Must have a :zeek:attr:`&publish_on_change` attribute.
	## batch_size: Number of :zeek:see:`Cluster::TableChangeInfo` records to use per event.
	global publish_table: function(
		topic: string,
		table_val: any,
		batch_size: count &default=default_publish_table_batch_size
	): bool;

}

@load base/bif/publish_on_change.bif

function publish_table(topic: string, table_val: any, batch_size: count): bool
	{
	return __publish_table(topic, table_val, batch_size);
	}

# Event for processing change events from other nodes.
#
# If you need information about the sending node or additional information,
# that is not part of of the :zeek:see:`Cluster::TableChangeInfo`, look into adding
# event metadata.
event table_change_infos(tcheader: TableChangeHeader, tcinfos: TableChangeInfos)
	{
	# Do not apply changes that come from this node itself. This should only
	# happen in the case when forward_table_change_infos() was used which
	# should only be used with Broker.
	if ( tcheader$node_id == Cluster::node_id() )
		{
		if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
			Reporter::warning("Got table_change_infos() event from self");

		return;
		}
	# Allow hooking the processing of table change infos. Could
	# consider replicating the changes to a separate system, etc.
	#
	# If an implementation breaks, nothing will happen.
	if ( ! hook apply_table_change_infos_policy(tcheader, tcinfos) )
		return;

	apply_table_change_infos(tcheader, tcinfos);
	}

# This is used by the manager when it receives the forward_table_change_infos() event
# event below to determine if the event is also destined to itself. We insert all
# topic prefixes into a table[pattern] for easy lookup in forward_table_change_infos().
global topic_prefixes: table[pattern] of string;

hook Cluster::on_subscribe(topic: string)
	{
	# Build a prefix pattern for the topic.
	local pat = string_to_pattern(convert_for_pattern(topic) + ".*", F);
	topic_prefixes[pat] = topic;
	}

# This event is published by workers to the manager when Broker is used because
# workers do not see each others remote events, but this is required for proper
# &publish_on_change functionality.
#
# XXX: Note that the manager raises table_change_infos() locally if it recognizes
#      to_topic matching a topic its subscribed to. This is a bit unfortunate and
#      the culprit is really that worker-to-worker publish/subscribe does not work
#      for Broker. If you find this is your bottleneck, consider trying ZeroMQ.
event forward_table_change_infos(tcheader: TableChangeHeader, tcinfos: TableChangeInfos, to_topic: string)
	{
	if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
		Reporter::fatal(fmt("forward_table_change_infos unexpected for %s", Cluster::backend));

	if ( Cluster::local_node_type() != Cluster::MANAGER )
		Reporter::fatal(fmt("%s got unexpected event forward_table_change_infos to=%s id=%s)",
		                    Cluster::node, to_topic, tcheader$id));

	# Forward the event to to_topic verbatim.
	Cluster::publish(to_topic, table_change_infos, tcheader, tcinfos);

	# Determine if the manager itself should also receive the event.
	# See the topic_prefixes construction above. This is a table[pattern]
	# that contains contains prefix patterns for the topics the manager is
	# subscribed to. If the to_topic matches any prefix, raise the forwarded
	# event locally, too.
	if ( to_topic in topic_prefixes )
		event table_change_infos(tcheader, tcinfos);
	}

event zeek_init()
	{
	# This needs to be in sync with the code in src/cluster/PublishOnChangeState.cc
	# right now. Moving forward it'd be nice to just have Cluster::join_topic(vector)
	# or Cluster::join_topic(va_args: any).
	local topic_separator = "/";
	local topic = join_string_vec(vector("zeek", "table", ""), topic_separator);
	Cluster::subscribe(topic);

	# If Broker is enabled and this is a worker, send changes through the manager.
	if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER && Cluster::local_node_type() == Cluster::WORKER )
		set_table_change_infos_forward_topic(Cluster::manager_topic);
	}
