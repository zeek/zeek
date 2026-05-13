##! Just a pubsub netcontrol plugin that uses zeek:see`Cluster::publish` and
##! native support for batching for the publishing side to make downstream
##! processing more efficient at the expense of a slight delay.

@load ../main
@load ../plugin
@load base/utils/batch-queue

module NetControl;

export {
	type PubSubConfig: record {
		## The topic to publish to.
		request_topic: string;
		## The topic on which to expect replies.
		reply_topic: string;

		max_batch_size: count &default=100;
		max_batch_delay: interval &default=10msec;
	};

	##
	const default_batch_queue_max_size = 200 &redef;
	const default_batch_queue_max_delay = 5msec &redef;

	type PubSubRule: record {
		ty: RuleType;
		arg: string;  # stringified address
		comment: string &optional;
		rule_id: string;
		r: Rule;
	};

	## Events that are published via Cluster::publish() to the configured request topic.
	## Replies are expected on reply_topic.
	global pubsub_add_rules: event(reply_topic: string, id: count, rules: vector of PubSubRule);
	global pubsub_remove_rules: event(reply_topic: string, id: count, rules: vector of PubSubRule);

	# Extend the BatchQeuue with information about the netcontrol
	# plugin instance so we can look these up during the flush
	# allback execution.
	redef record BatchQueue += {
		pubsub_id: count &optional;
		pubsub_config: PubSubConfig &optional;
	};

	## Holds the add and remove queues.
	type PubSubBatchQueues: record {
		add_queue: BatchQueue &default=batch_queue_new(
			$max_size=default_batch_queue_max_size,
			$max_delay=default_batch_queue_max_delay,
			$flush_callback=function(bq: BatchQueue, elements: vector of any) {
				local request_topic = bq$pubsub_config$request_topic;
				local reply_topic = bq$pubsub_config$reply_topic;
				local psrs = elements as vector of PubSubRule;

				Cluster::publish(request_topic, pubsub_add_rules, reply_topic, bq$pubsub_id, psrs);
			}
		);
		remove_queue: BatchQueue &default=batch_queue_new(
			$max_size=default_batch_queue_max_size,
			$max_delay=default_batch_queue_max_delay,
			$flush_callback=function(bq: BatchQueue, elements: vector of any)
				{
				local request_topic = bq$pubsub_config$request_topic;
				local reply_topic = bq$pubsub_config$reply_topic;
				local psrs = elements as vector of PubSubRule;  # pub sub rules
				Cluster::publish(request_topic, pubsub_remove_rules, reply_topic, bq$pubsub_id, psrs);
				}
		);
	};

	## Instantiates the pubsub plugin.
	global create_pubsub: function(config: PubSubConfig) : PluginState;

	redef record PluginState += {
		pubsub_config: PubSubConfig &optional;
		# Same pattern as in acld.zeek
		pubsub_id: count &optional;
	};

	## Events that should arrive back on reply_topic with the Rule
	## provided back from the client.
	global pubsub_rule_added: event(id: count, r: Rule, msg: string);
	global pubsub_rule_removed: event(id: count, r: Rule, msg: string);
	global pubsub_rule_exists: event(id: count, r: Rule, msg: string);
	global pubsub_rule_error: event(id: count, r: Rule, msg: string);
}

global netcontrol_pubsub_request_topics: set[string] = set();
global netcontrol_pubsub_reply_topics: set[string] = set();
global netcontrol_pubsub_id: table[count] of PluginState = table();
global netcontrol_pubsub_batch_queues: table[count] of PubSubBatchQueues = table();
global netcontrol_pubsub_current_id: count = 0;

### TODO: Should use a batched version to avoid sending one event per rule.
### TODO: pubsub_rule_result(id: count, r: Rule: result: enum, msg: string)
###       might also be a nicer API then having one event per outcome, would
###       avoid a bunch of duplicated checks.
### TODO: Could also batch multiple rules into a single event to avoid
###       the extra overhead, given add_rules works this way, might make
###       more sense.
event NetControl::pubsub_rule_added(id: count, r: Rule, msg: string)
	{
	if ( id !in netcontrol_pubsub_id )
		{
		Reporter::error(fmt("NetControl PubSub plugin with id %d not found, aborting", id));
		return;
		}

	local p = netcontrol_pubsub_id[id];

	event NetControl::rule_added(r, p, msg);
	}

event NetControl::pubsub_rule_exists(id: count, r: Rule, msg: string)
	{
	if ( id !in netcontrol_pubsub_id )
		{
		Reporter::error(fmt("NetControl PubSub plugin with id %d not found, aborting", id));
		return;
		}

	local p = netcontrol_pubsub_id[id];

	event NetControl::rule_exists(r, p, msg);
	}

event NetControl::pubsub_rule_removed(id: count, r: Rule, msg: string)
	{
	if ( id !in netcontrol_pubsub_id )
		{
		Reporter::error(fmt("NetControl acld plugin with id %d not found, aborting", id));
		return;
		}

	local p = netcontrol_pubsub_id[id];

	event NetControl::rule_removed(r, p, msg);
	}

event NetControl::acld_rule_error(id: count, r: Rule, msg: string)
	{
	if ( id !in netcontrol_pubsub_id )
		{
		Reporter::error(fmt("NetControl acld plugin with id %d not found, aborting", id));
		return;
		}

	local p = netcontrol_pubsub_id[id];

	event NetControl::rule_error(r, p, msg);
	}

function pubsub_add_rule_fun(p: PluginState, r: Rule) : bool
	{
	# Can only do drop.
	if ( r$ty != DROP )
		return F;

	local e = r$entity;
	if ( e$ty != ADDRESS )
		return F;

	# ip is actually a subnet!
	local ip = cat(e$ip);
	local psr = PubSubRule($ty=r$ty, $arg=ip, $rule_id=r$id, $r=r);
	if ( r?$location )  # Derived from acl.zeek, not sure that's awesome.
		psr$comment = r$location;

	local q = netcontrol_pubsub_batch_queues[p$pubsub_id]$add_queue;
	batch_queue_add(q, psr);
	return T;
	}

function pubsub_remove_rule_fun(p: PluginState, r: Rule, reason: string) : bool
	{
	# Can only do drop.
	if ( r$ty != DROP )
		return F;

	local e = r$entity;
	if ( e$ty != ADDRESS )
		return F;

	# ip is actually a subnet!
	local ip = cat(e$ip);
	local psr = PubSubRule($ty=r$ty, $arg=ip, $rule_id=r$id, $r=r);
	if ( r?$location )  # Derived from acl.zeek remove_rule_fun(), not sure that's awesome.
		psr$comment = fmt("%s (%s)", reason, r$location);
	else
		psr$comment = reason;

	local q = netcontrol_pubsub_batch_queues[p$pubsub_id]$remove_queue;
	batch_queue_add(q, psr);
	return T;
	}

function pubsub_init(p: PluginState)
	{
	Cluster::subscribe(p$pubsub_config$reply_topic);
	Reporter::info(fmt("initialized %d", p$pubsub_id));
	plugin_activated(p);
	}

function pubsub_name(p: PluginState) : string
	{
	return fmt("PubSub-%s", p$pubsub_config$request_topic);
	}

global pubsub_plugin = Plugin(
	$name=pubsub_name,
	$can_expire = F,
	$add_rule = pubsub_add_rule_fun,
	$remove_rule = pubsub_remove_rule_fun,
	$init = pubsub_init
);

function create_pubsub(config: PubSubConfig) : PluginState
	{
	if ( config$reply_topic in netcontrol_pubsub_reply_topics )
		Reporter::warning(fmt("Topic %s was added to NetControl PubSub plugin twice.", config$reply_topic));
	else
		add netcontrol_pubsub_reply_topics[config$reply_topic];

	if ( config$request_topic in netcontrol_pubsub_request_topics )
		Reporter::warning(fmt("Request topic %s was added to NetControl PubSub plugin twice.", config$request_topic));
	else
		add netcontrol_pubsub_request_topics[config$request_topic];

	local p = PluginState($pubsub_config=config, $plugin=pubsub_plugin, $pubsub_id=netcontrol_pubsub_current_id);
	netcontrol_pubsub_id[netcontrol_pubsub_current_id] = p;

	# Attach pubsub_id and pubsub_config to the batch queues
	# so we have access to them through the callbacks. This
	# is a bit gnarly.
	local pubsub_queues = PubSubBatchQueues();
	pubsub_queues$add_queue$pubsub_id = p$pubsub_id;
	pubsub_queues$add_queue$pubsub_config = p$pubsub_config;
	pubsub_queues$remove_queue$pubsub_id = p$pubsub_id;
	pubsub_queues$remove_queue$pubsub_config = p$pubsub_config;
	netcontrol_pubsub_batch_queues[netcontrol_pubsub_current_id] = pubsub_queues;

	++netcontrol_pubsub_current_id;
	return p;
	}
