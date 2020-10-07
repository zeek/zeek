##! Implementation of the drop functionality for NetControl.

@load ./main

module NetControl;

export {
	redef enum Log::ID += { DROP_LOG };

	global log_policy_drop: Log::PolicyHook;

	## Stops all packets involving an IP address from being forwarded.
	##
	## a: The address to be dropped.
	##
	## t: How long to drop it, with 0 being indefinitely.
	##
	## location: An optional string describing where the drop was triggered.
	##
	## Returns: The id of the inserted rule on success and zero on failure.
	global drop_address: function(a: addr, t: interval, location: string &default="") : string;

	## Stops all packets involving a connection address from being forwarded.
	##
	## c: The connection to be dropped.
	##
	## t: How long to drop it, with 0 being indefinitely.
	##
	## location: An optional string describing where the drop was triggered.
	##
	## Returns: The id of the inserted rule on success and zero on failure.
	global drop_connection: function(c: conn_id, t: interval, location: string &default="") : string;

	type DropInfo: record {
		## Time at which the recorded activity occurred.
		ts: time		&log;
		## ID of the rule; unique during each Zeek run.
		rule_id: string  &log;
		orig_h: addr 	&log;	##< The originator's IP address.
		orig_p: port 	&log &optional;	##< The originator's port number.
		resp_h: addr	&log &optional;	##< The responder's IP address.
		resp_p: port	&log &optional;	##< The responder's port number.
		## Expiry time of the shunt.
		expire: interval &log;
		## Location where the underlying action was triggered.
		location: string	&log &optional;
	};

	## Hook that allows the modification of rules passed to drop_* before they
	## are passed on. If one of the hooks uses break, the rule is ignored.
	##
	## r: The rule to be added.
	global NetControl::drop_rule_policy: hook(r: Rule);

	## Event that can be handled to access the :zeek:type:`NetControl::ShuntInfo`
	## record as it is sent on to the logging framework.
	global log_netcontrol_drop: event(rec: DropInfo);
}

event zeek_init() &priority=5
	{
	Log::create_stream(NetControl::DROP_LOG, [$columns=DropInfo, $ev=log_netcontrol_drop, $path="netcontrol_drop", $policy=log_policy_drop]);
	}

function drop_connection(c: conn_id, t: interval, location: string &default="") : string
	{
	local e: Entity = [$ty=CONNECTION, $conn=c];
	local r: Rule = [$ty=DROP, $target=FORWARD, $entity=e, $expire=t, $location=location];

	if ( ! hook NetControl::drop_rule_policy(r) )
		return "";

	local id = add_rule(r);

	# Error should already be logged
	if ( id == "" )
		return id;

	local log = DropInfo($ts=network_time(), $rule_id=id, $orig_h=c$orig_h, $orig_p=c$orig_p, $resp_h=c$resp_h, $resp_p=c$resp_p, $expire=t);

	if ( location != "" )
		log$location=location;

	Log::write(DROP_LOG, log);

	return id;
	}

function drop_address(a: addr, t: interval, location: string &default="") : string
	{
	local e: Entity = [$ty=ADDRESS, $ip=addr_to_subnet(a)];
	local r: Rule = [$ty=DROP, $target=FORWARD, $entity=e, $expire=t, $location=location];

	if ( ! hook NetControl::drop_rule_policy(r) )
		return "";

	local id = add_rule(r);

	# Error should already be logged
	if ( id == "" )
		return id;

	local log = DropInfo($ts=network_time(), $rule_id=id, $orig_h=a, $expire=t);

	if ( location != "" )
		log$location=location;

	Log::write(DROP_LOG, log);

	return id;
	}

