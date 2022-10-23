##! Defines an interface for managing pools of cluster nodes.  Pools are
##! a useful way to distribute work or data among nodes within a cluster.

@load ./main
@load base/utils/hash_hrw

module Cluster;

export {
	## Store state of a cluster within the context of a work pool.
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

	## A pool specification.
	type PoolSpec: record {
		## A topic string that can be used to reach all nodes within a pool.
		topic: string &default = "";
		## The type of nodes that are contained within the pool.
		node_type: Cluster::NodeType &default = Cluster::PROXY;
		## The maximum number of nodes that may belong to the pool.
		## If not set, then all available nodes will be added to the pool,
		## else the cluster framework will automatically limit the pool
		## membership according to the threshold.
		max_nodes: count &optional;
		## Whether the pool requires exclusive access to nodes.  If true,
		## then *max_nodes* nodes will not be assigned to any other pool.
		## When using this flag, *max_nodes* must also be set.
		exclusive: bool &default = F;
	};

	type PoolNodeTable: table[string] of PoolNode;
	type RoundRobinTable: table[string] of int;

	## A pool used for distributing data/work among a set of cluster nodes.
	type Pool: record {
		## The specification of the pool that was used when registering it.
		spec: PoolSpec &default = PoolSpec();
		## Nodes in the pool, indexed by their name (e.g. "manager").
		nodes: PoolNodeTable &default = PoolNodeTable();
		## A list of nodes in the pool in a deterministic order.
		node_list: vector of PoolNode &default = vector();
		## The Rendezvous hashing structure.
		hrw_pool: HashHRW::Pool &default = HashHRW::Pool();
		## Round-Robin table indexed by arbitrary key and storing the next
		## index of *node_list* that will be eligible to receive work (if it's
		## alive at the time of next request).
		rr_key_seq: RoundRobinTable &default = RoundRobinTable();
		## Number of pool nodes that are currently alive.
		alive_count: count &default = 0;
	};

	## The specification for :zeek:see:`Cluster::proxy_pool`.
	global proxy_pool_spec: PoolSpec =
		PoolSpec($topic = "zeek/cluster/pool/proxy",
				 $node_type = Cluster::PROXY) &redef;

	## The specification for :zeek:see:`Cluster::worker_pool`.
	global worker_pool_spec: PoolSpec =
		PoolSpec($topic = "zeek/cluster/pool/worker",
				 $node_type = Cluster::WORKER) &redef;

	## The specification for :zeek:see:`Cluster::logger_pool`.
	global logger_pool_spec: PoolSpec =
		PoolSpec($topic = "zeek/cluster/pool/logger",
				 $node_type = Cluster::LOGGER) &redef;

	## A pool containing all the proxy nodes of a cluster.
	## The pool's node membership/availability is automatically
	## maintained by the cluster framework.
	global proxy_pool: Pool;

	## A pool containing all the worker nodes of a cluster.
	## The pool's node membership/availability is automatically
	## maintained by the cluster framework.
	global worker_pool: Pool;

	## A pool containing all the logger nodes of a cluster.
	## The pool's node membership/availability is automatically
	## maintained by the cluster framework.
	global logger_pool: Pool;

	## Registers and initializes a pool.
	global register_pool: function(spec: PoolSpec): Pool;

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
	##      requesting the topic.  e.g. consider using a name-spaced key
	##      like "Intel::cluster_rr_key" if you need to guarantee that
	##      a group of messages get distributed in a well-defined pattern
	##      without other messages being interleaved within the round-robin.
	##      Usually sharing the default key is fine for load-balancing
	##      purposes.
	##
	## Returns: a topic string associated with a cluster node that is alive,
	##          or an empty string if nothing is alive.
	global rr_topic: function(pool: Pool, key: string &default=""): string;

	## Distributes log message topics among logger nodes via round-robin.
	## This will be automatically assigned to :zeek:see:`Broker::log_topic`
	## if :zeek:see:`Cluster::enable_round_robin_logging` is enabled.
	## If no logger nodes are active, then this will return the value
	## of :zeek:see:`Broker::default_log_topic`.
	global rr_log_topic: function(id: Log::ID, path: string): string;
}

## Initialize a node as a member of a pool.
##
## pool: the pool to which the node will belong.
##
## name: the name of the node (e.g. "manager").
##
## Returns: F if a node of the same name already exists in the pool, else T.
global init_pool_node: function(pool: Pool, name: string): bool;

## Mark a pool node as alive/online/available. :zeek:see:`Cluster::hrw_topic`
## will distribute keys to nodes marked as alive.
##
## pool: the pool to which the node belongs.
##
## name: the name of the node to mark.
##
## Returns: F if the node does not exist in the pool, else T.
global mark_pool_node_alive: function(pool: Pool, name: string): bool;

## Mark a pool node as dead/offline/unavailable. :zeek:see:`Cluster::hrw_topic`
## will not distribute keys to nodes marked as dead.
##
## pool: the pool to which the node belongs.
##
## name: the name of the node to mark.
##
## Returns: F if the node does not exist in the pool, else T.
global mark_pool_node_dead: function(pool: Pool, name: string): bool;

global registered_pools: vector of Pool = vector();

function register_pool(spec: PoolSpec): Pool
	{
	local rval = Pool($spec = spec);
	registered_pools += rval;
	return rval;
	}

function hrw_topic(pool: Pool, key: any): string
	{
	if ( |pool$hrw_pool$sites| == 0 )
		return "";

	local site = HashHRW::get_site(pool$hrw_pool, key);
	local pn: PoolNode = site$user_data;
	return Cluster::node_topic(pn$name);
	}

function rr_topic(pool: Pool, key: string): string
	{
	if ( key !in pool$rr_key_seq )
		pool$rr_key_seq[key] = 0;

	local next_idx = pool$rr_key_seq[key];
	local start = next_idx;
	local rval = "";

	if ( next_idx >= |pool$node_list| )
		return rval;

	while ( T )
		{
		local pn = pool$node_list[next_idx];

		++next_idx;

		if ( next_idx == |pool$node_list| )
			next_idx = 0;

		if ( pn$alive )
			{
			rval = Cluster::node_topic(pn$name);
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
	for ( i in registered_pools )
		{
		local pool = registered_pools[i];

		if ( name in pool$nodes )
			mark_pool_node_alive(pool, name);
		}
	}

event Cluster::node_down(name: string, id: string) &priority=10
	{
	for ( i in registered_pools )
		{
		local pool = registered_pools[i];

		if ( name in pool$nodes )
			mark_pool_node_dead(pool, name);
		}
	}

function site_id_in_pool(pool: Pool, site_id: count): bool
	{
	for ( i, pn in pool$nodes )
		{
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
			pool$node_list += pn;

			if ( pn$alive )
				++pool$alive_count;

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

	if ( ! pn$alive )
		{
		pn$alive = T;
		++pool$alive_count;
		}

	HashHRW::add_site(pool$hrw_pool, HashHRW::Site($id=pn$site_id, $user_data=pn));
	return T;
	}

function mark_pool_node_dead(pool: Pool, name: string): bool
	{
	if ( name !in pool$nodes )
		return F;

	local pn = pool$nodes[name];

	if ( pn$alive )
		{
		pn$alive = F;
		--pool$alive_count;
		}

	HashHRW::rem_site(pool$hrw_pool, HashHRW::Site($id=pn$site_id, $user_data=pn));
	return T;
	}

event zeek_init()
	{
	worker_pool = register_pool(worker_pool_spec);
	proxy_pool = register_pool(proxy_pool_spec);
	logger_pool = register_pool(logger_pool_spec);
	}

type PoolEligibilityTracking: record {
	eligible_nodes: vector of NamedNode &default = vector();
	next_idx: count &default = 0;
	excluded: count &default = 0;
};

global pool_eligibility: table[Cluster::NodeType] of PoolEligibilityTracking = table();

function pool_sorter(a: Pool, b: Pool): int
	{
	return strcmp(a$spec$topic, b$spec$topic);
	}

# Needs to execute before the zeek_init in setup-connections
event zeek_init() &priority=-5
	{
	if ( ! Cluster::is_enabled() )
		return;

	# Sorting now ensures the node distribution process is stable even if
	# there's a change in the order of time-of-registration between Zeek runs.
	sort(registered_pools, pool_sorter);

	pool_eligibility[Cluster::WORKER] =
		PoolEligibilityTracking($eligible_nodes = nodes_with_type(Cluster::WORKER));
	pool_eligibility[Cluster::PROXY] =
		PoolEligibilityTracking($eligible_nodes = nodes_with_type(Cluster::PROXY));
	pool_eligibility[Cluster::LOGGER] =
		PoolEligibilityTracking($eligible_nodes = nodes_with_type(Cluster::LOGGER));

	if ( manager_is_logger )
		{
		local mgr = nodes_with_type(Cluster::MANAGER);

		if ( |mgr| > 0 )
			{
			local eln = pool_eligibility[Cluster::LOGGER]$eligible_nodes;
			eln += mgr[0];
			}
		}

	local pool: Pool;
	local pet: PoolEligibilityTracking;
	local en: vector of NamedNode;

	for ( i in registered_pools )
		{
		pool = registered_pools[i];

		if ( pool$spec$node_type !in pool_eligibility )
			Reporter::fatal(fmt("invalid pool node type: %s", pool$spec$node_type));

		if ( ! pool$spec$exclusive )
			next;

		if ( ! pool$spec?$max_nodes )
			Reporter::fatal("Cluster::PoolSpec 'max_nodes' field must be set when using the 'exclusive' flag");

		pet = pool_eligibility[pool$spec$node_type];
		pet$excluded += pool$spec$max_nodes;
		}

	for ( nt, pet in pool_eligibility )
		{
		if ( pet$excluded > |pet$eligible_nodes| )
			Reporter::fatal(fmt("not enough %s nodes to satisfy pool exclusivity requirements: need %d nodes", nt, pet$excluded));
		}

	for ( i in registered_pools )
		{
		pool = registered_pools[i];

		if ( ! pool$spec$exclusive )
			next;

		pet = pool_eligibility[pool$spec$node_type];

		local e = 0;

		while ( e < pool$spec$max_nodes )
			{
			init_pool_node(pool, pet$eligible_nodes[e]$name);
			++e;
			}

		local nen: vector of NamedNode = vector();

		for ( j in pet$eligible_nodes )
			{
			if ( j < e )
				next;

			nen += pet$eligible_nodes[j];
			}

		pet$eligible_nodes = nen;
		}

	for ( i in registered_pools )
		{
		pool = registered_pools[i];

		if ( pool$spec$exclusive )
			next;

		pet = pool_eligibility[pool$spec$node_type];
		local nodes_to_init = |pet$eligible_nodes|;

		if ( pool$spec?$max_nodes &&
			 pool$spec$max_nodes < |pet$eligible_nodes| )
			nodes_to_init = pool$spec$max_nodes;

		local nodes_inited = 0;

		while ( nodes_inited < nodes_to_init )
			{
			init_pool_node(pool, pet$eligible_nodes[pet$next_idx]$name);
			++nodes_inited;
			++pet$next_idx;

			if ( pet$next_idx == |pet$eligible_nodes| )
				pet$next_idx = 0;
			}
		}
	}
