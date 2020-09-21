##! Implementation of the shunt functionality for NetControl.

module NetControl;

@load ./main

export {
	redef enum Log::ID += { SHUNT };

	global log_policy_shunt: Log::PolicyHook;

	## Stops forwarding a uni-directional flow's packets to Zeek.
	##
	## f: The flow to shunt.
	##
	## t: How long to leave the shunt in place, with 0 being indefinitely.
	##
	## location: An optional string describing where the shunt was triggered.
	##
	## Returns: The id of the inserted rule on success and zero on failure.
	global shunt_flow: function(f: flow_id, t: interval, location: string &default="") : string;

	type ShuntInfo: record {
		## Time at which the recorded activity occurred.
		ts: time &log;
		## ID of the rule; unique during each Zeek run.
		rule_id: string  &log;
		## Flow ID of the shunted flow.
		f: flow_id &log;
		## Expiry time of the shunt.
		expire: interval &log;
		## Location where the underlying action was triggered.
		location: string &log &optional;
	};

	## Event that can be handled to access the :zeek:type:`NetControl::ShuntInfo`
	## record as it is sent on to the logging framework.
	global log_netcontrol_shunt: event(rec: ShuntInfo);
}

event zeek_init() &priority=5
	{
	Log::create_stream(NetControl::SHUNT, [$columns=ShuntInfo, $ev=log_netcontrol_shunt, $path="netcontrol_shunt", $policy=log_policy_shunt]);
	}

function shunt_flow(f: flow_id, t: interval, location: string &default="") : string
	{
	local flow = NetControl::Flow(
		$src_h=addr_to_subnet(f$src_h),
		$src_p=f$src_p,
		$dst_h=addr_to_subnet(f$dst_h),
		$dst_p=f$dst_p
	);
	local e: Entity = [$ty=FLOW, $flow=flow];
	local r: Rule = [$ty=DROP, $target=MONITOR, $entity=e, $expire=t, $location=location];

	local id = add_rule(r);

	# Error should already be logged
	if ( id == "" )
		return id;

	local log = ShuntInfo($ts=network_time(), $rule_id=id, $f=f, $expire=t);
	if ( location != "" )
		log$location=location;

	Log::write(SHUNT, log);

	return id;
	}

