##! Helper functions for table synchronization in a Zeek cluster.
##!
##! This module explores the idea of using the ``&on_change`` attribute
##! on tables for state propagation in a Zeek cluster.
##!
##! The :zeek:see:`Cluster::Table::publish_new_element` builtin function
##! can be used as the ``&on_change`` function and will internally publish
##! any new elements of a table to a table specific topic. For example,
##! ``zeek/table/<module>::<table_identifier>``.
##! :zeek:see:`Cluster::Table::publish_new_element` is meant for
##! state dissemination, but not guaranteed synchronization. Existence
##! checks or cluster-wide rate-limiting are examples for which this should
##! work well.
##!
##! When a node crashes and restarts, it'll start with an empty table. If
##! you require seeding a node's table after a crash, implement a
##! :zeek:see:`Cluster::node_up` handler. Beware that publishing a full
##! table likely incurs a performance penalty, but for tables with a
##! few thousand entries might be reasonable.
##!
##! Tables using the ``&on_change=Cluster::Table::publish_new_element``
##! should have ``&write_expire`` or ``&read_expire`` attribute to ensure
##! eventual expiration of unused entries.

module Cluster::Table;

@load base/bif/cluster_table.bif

export {
	type NewElement: record {
		## The key value. Internally tables and sets use ListVal
		## instances but for cluster communication we use vector
		## of any.
		key: vector of any;
		## The initial value of the new element. If id resolves
		## to a set, this field should conventionally be set to true.
		value: any;
	};

	## Internal event used to receive new elements for the table
	## identified by **id**.
	global elements_new_internal: event(id: string, new_elements: vector of NewElement);

	## The separator to use for topics. This should really live in the
	## top-level cluster module, but that might need to wait until 8.2.
	const topic_separator = "/" &redef;
}

event elements_new_internal(id: string, new_elements: vector of NewElement)
	{
	insert_elements_new(id, new_elements);

	# When running under Broker, the manager re-publishes the inserts
	# to workers. Topology awareness and all. This isn't needed for
	# ZeroMQ where there exists global publish/subscribe visibility.
	if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER && Cluster::local_node_type() == Cluster::MANAGER )
		Cluster::publish(Cluster::worker_topic, elements_new_internal, id, new_elements);
	}

event zeek_init()
	{
	local topic = join_string_vec(vector("zeek", "table", ""), topic_separator);
	Cluster::subscribe(topic);
	}
