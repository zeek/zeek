##! Defines an interface for managing pools of cluster nodes.  Pools are
##! are useful way to distribute work or data among nodes within a cluster.

@load ./main
@load base/utils/hash_hrw

module Cluster;

export {
	## Store state of a cluster within within the context of a work pool.
	type PoolNode: record {
		## The node name (e.g. "manager").
		name: string;
		## An alias of *name* used to prevent hashing collisions when creating
		## *site_id*.
		alias: string;
		## A 32-bit unique identifier for the pool node, derived from name/alias.
		site_id: count;
		## Whether the node is currently alive and can receive work.
		alive: bool &default=F;
	};

	## A pool used for distributing data/work among a set of cluster nodes.
	type Pool: record {
		## Nodes in the pool, indexed by their name (e.g. "manager").
		nodes: table[string] of PoolNode;
		## A list of nodes in the pool in a deterministic order.
		node_list: vector of PoolNode;
		## The Rendezvous hashing structure.
		hrw_pool: HashHRW::Pool;
		## Round-Robin table indexed by arbitrary key and storing the next
		## index of *node_list* that will be eligible to receive work (if it's
		## alive at the time of next request).
		rr_key_seq: table[string] of int;
	};

	## A pool containing all the proxy nodes of a cluster.
	global proxy_pool: Pool;

	## A pool containing all the worker nodes of a cluster.
	global worker_pool: Pool;

	## A pool containing all the logger nodes of a cluster.
	global logger_pool: Pool;

	## Initialize a node as a member of a pool.
	##
	## pool: the pool to which the node will belong.
	##
	## name: the name of the node (e.g. "manager").
	##
	## Returns: F if a node of the same name already exists in the pool, else T.
	global init_pool_node: function(pool: Pool, name: string): bool;

	## Mark a pool node as alive/online/available. :bro:see:`Cluster::hrw_topic`
	## will distribute keys to nodes marked as alive.
	##
	## pool: the pool to which the node belongs.
	##
	## name: the name of the node to mark.
	##
	## Returns: F if the node does not exist in the pool, else T.
	global mark_pool_node_alive: function(pool: Pool, name: string): bool;

	## Mark a pool node as dead/offline/unavailable. :bro:see:`Cluster::hrw_topic`
	## will not distribute keys to nodes marked as dead.
	##
	## pool: the pool to which the node belongs.
	##
	## name: the name of the node to mark.
	##
	## Returns: F if the node does not exist in the pool, else T.
	global mark_pool_node_dead: function(pool: Pool, name: string): bool;

	## Retrieve the topic associated with the node mapped via Rendezvous hash
	## of an arbitrary key.
	##
	## pool: the pool of nodes to consider.
	##
	## key: data used for input to the hashing function that will uniformly
	##      distribute keys among available nodes.
	##
	## Returns: a topic string associated with a cluster node that is alive
	##          or an empty string if nothing is alive.
	global hrw_topic: function(pool: Pool, key: any): string;

	## Retrieve the topic associated with the node in a round-robin fashion.
	##
	## pool: the pool of nodes to consider.
	##
	## key: an arbitrary string to identify the purpose for which you're
	##      requesting the topic.  e.g. consider using namespacing of your script
	##      like "Intel::cluster_rr_key".
	##
	## Returns: a topic string associated with a cluster node that is alive,
	##          or an empty string if nothing is alive.
	global rr_topic: function(pool: Pool, key: string): string;

	## Distributes log message topics among logger nodes via round-robin.
	## This will be automatically assigned to :bro:see:`Broker::log_topic`
	## if :bro:see:`Cluster::enable_round_robin_logging` is enabled.
	## If no logger nodes are active, then this will return the value
	## of :bro:see:`Broker::default_log_topic`.
	global rr_log_topic: function(id: Log::ID, path: string): string;
}

function hrw_topic(pool: Pool, key: any): string
	{
	if ( |pool$hrw_pool$sites| == 0 )
		return "";

	local site = HashHRW::get_site(pool$hrw_pool, key);
	local pn: PoolNode = site$user_data;
	return node_topic_prefix + pn$name;
	}

function rr_topic(pool: Pool, key: string): string
	{
	if ( key !in pool$rr_key_seq )
		pool$rr_key_seq[key] = 0;

	local next_idx = pool$rr_key_seq[key];
	local start = next_idx;
	local rval = "";

	while ( T )
		{
		local pn = pool$node_list[next_idx];

		++next_idx;

		if ( next_idx == |pool$node_list| )
			next_idx = 0;

		if ( pn$alive )
			{
			rval = node_topic_prefix + pn$name;
			break;
			}

		if ( next_idx == start )
			# no nodes alive
			break;
		}

	pool$rr_key_seq[key] = next_idx;
	return rval;
	}

function rr_log_topic(id: Log::ID, path: string): string
	{
	local rval = rr_topic(logger_pool, "Cluster::rr_log_topic");

	if ( rval != "" )
		return rval;

	rval = Broker::default_log_topic(id, path);
	return rval;
	}

event Cluster::node_up(name: string, id: string) &priority=10
	{
	if ( name !in nodes )
		{
		Reporter::error(fmt("unexpected node name: %s", name));
		return;
		}

	local n = nodes[name];

	switch ( n$node_type ) {
	case WORKER:
		mark_pool_node_alive(worker_pool, name);
		break;
	case PROXY:
		mark_pool_node_alive(proxy_pool, name);
		break;
	case LOGGER:
		mark_pool_node_alive(logger_pool, name);
		break;
	case MANAGER:
		if ( manager_is_logger )
			mark_pool_node_alive(logger_pool, name);
		break;
	}
	}

event Cluster::node_down(name: string, id: string) &priority=10
	{
	if ( name !in nodes )
		{
		Reporter::error(fmt("unexpected node name: %s", name));
		return;
		}

	local n = nodes[name];

	switch ( n$node_type ) {
	case WORKER:
		mark_pool_node_dead(worker_pool, name);
		break;
	case PROXY:
		mark_pool_node_dead(proxy_pool, name);
		break;
	case LOGGER:
		mark_pool_node_dead(logger_pool, name);
		break;
	case MANAGER:
		if ( manager_is_logger )
			mark_pool_node_dead(logger_pool, name);
		break;
	}
	}

function site_id_in_pool(pool: Pool, site_id: count): bool
	{
	for ( i in pool$nodes )
		{
		local pn = pool$nodes[i];

		if ( pn$site_id == site_id )
			return T;
		}

	return F;
	}

function init_pool_node(pool: Pool, name: string): bool
	{
	if ( name in pool$nodes )
		return F;

	local loop = T;
	local c = 0;

	while ( loop )
		{
		# site id collisions are unlikely, but using aliases handles it...
		# alternatively could terminate and ask user to pick a new node name
		# if it ends up colliding.
		local alias = name + fmt(".%s", c);
		local site_id = fnv1a32(alias);

		if ( site_id_in_pool(pool, site_id) )
			++c;
		else
			{
			local pn = PoolNode($name=name, $alias=alias, $site_id=site_id,
			                    $alive=Cluster::node == name);
			pool$nodes[name] = pn;
			pool$node_list[|pool$node_list|] = pn;
			loop = F;
			}
		}

	return T;
	}

function mark_pool_node_alive(pool: Pool, name: string): bool
	{
	if ( name !in pool$nodes )
		return F;

	local pn = pool$nodes[name];
	pn$alive = T;
	HashHRW::add_site(pool$hrw_pool, HashHRW::Site($id=pn$site_id, $user_data=pn));
	return T;
	}

function mark_pool_node_dead(pool: Pool, name: string): bool
	{
	if ( name !in pool$nodes )
		return F;

	local pn = pool$nodes[name];
	pn$alive = F;
	HashHRW::rem_site(pool$hrw_pool, HashHRW::Site($id=pn$site_id, $user_data=pn));
	return T;
	}

event bro_init() &priority=10
	{
	local names: vector of string = vector();

	for ( name in nodes )
		names[|names|] = name;

	names = sort(names, strcmp);

	for ( i in names )
		{
		name = names[i];
		local n = nodes[name];

		switch ( n$node_type ) {
		case WORKER:
			init_pool_node(worker_pool, name);
			break;
		case PROXY:
			init_pool_node(proxy_pool, name);
			break;
		case LOGGER:
			init_pool_node(logger_pool, name);
			break;
		case MANAGER:
			if ( manager_is_logger )
				init_pool_node(logger_pool, name);
			break;
		}
		}
	}
