##! This file defines the types that are used by the NetControl framework.
##!
##! The most important type defined in this file is :zeek:see:`NetControl::Rule`,
##! which is used to describe all rules that can be expressed by the NetControl framework.

module NetControl;

export {
	## The default priority that is used when creating rules.
	option default_priority: int = +0;

	## The default priority that is used when using the high-level functions to
	## push whitelist entries to the backends (:zeek:see:`NetControl::whitelist_address` and
	## :zeek:see:`NetControl::whitelist_subnet`).
	##
	## Note that this priority is not automatically used when manually creating rules
	## that have a :zeek:see:`NetControl::RuleType` of :zeek:enum:`NetControl::WHITELIST`.
	const whitelist_priority: int = +5 &redef;

	## Type defining the entity that a rule applies to.
	type EntityType: enum {
		ADDRESS,	##< Activity involving a specific IP address.
		CONNECTION,	##< Activity involving all of a bi-directional connection's activity.
		FLOW,		##< Activity involving a uni-directional flow's activity. Can contain wildcards.
		MAC,		##< Activity involving a MAC address.
	};

	## Flow is used in :zeek:type:`NetControl::Entity` together with :zeek:enum:`NetControl::FLOW` to specify
	## a uni-directional flow that a rule applies to.
	##
	## If optional fields are not set, they are interpreted as wildcarded.
	type Flow: record {
		src_h: subnet &optional;	##< The source IP address/subnet.
		src_p: port &optional;	##< The source port number.
		dst_h: subnet &optional;	##< The destination IP address/subnet.
		dst_p: port &optional;	##< The destination port number.
		src_m: string &optional;	##< The source MAC address.
		dst_m: string &optional;	##< The destination MAC address.
	};

	## Type defining the entity a rule is operating on.
	type Entity: record {
		ty: EntityType;			##< Type of entity.
		conn: conn_id &optional;	##< Used with :zeek:enum:`NetControl::CONNECTION`.
		flow: Flow &optional;	##< Used with :zeek:enum:`NetControl::FLOW`.
		ip: subnet &optional;		##< Used with :zeek:enum:`NetControl::ADDRESS` to specify a CIDR subnet.
		mac: string &optional;		##< Used with :zeek:enum:`NetControl::MAC`.
	};

	## Type defining the target of a rule.
	##
	## Rules can either be applied to the forward path, affecting all network traffic, or
	## on the monitor path, only affecting the traffic that is sent to Zeek. The second
	## is mostly used for shunting, which allows Zeek to tell the networking hardware that
	## it wants to no longer see traffic that it identified as benign.
	type TargetType: enum {
		FORWARD,	#< Apply rule actively to traffic on forwarding path.
		MONITOR,	#< Apply rule passively to traffic sent to Zeek for monitoring.
	};

	## Type of rules that the framework supports. Each type lists the extra
	## :zeek:type:`NetControl::Rule` fields it uses, if any.
	##
	## Plugins may extend this type to define their own.
	type RuleType: enum {
		## Stop forwarding all packets matching the entity.
		##
		## No additional arguments.
		DROP,

		## Modify all packets matching entity. The packets
		## will be modified according to the `mod` entry of
		## the rule.
		##
		MODIFY,

		## Redirect all packets matching entity to a different switch port,
		## given in the `out_port` argument of the rule.
		##
		REDIRECT,

		## Whitelists all packets of an entity, meaning no restrictions will be applied.
		## While whitelisting is the default if no rule matches, this type can be
		## used to override lower-priority rules that would otherwise take effect for the
		## entity.
		WHITELIST,
	};

	## Type for defining a flow modification action.
	type FlowMod: record {
		src_h: addr &optional;	##< The source IP address.
		src_p: count &optional;	##< The source port number.
		dst_h: addr &optional;	##< The destination IP address.
		dst_p: count &optional;	##< The destination port number.
		src_m: string &optional;	##< The source MAC address.
		dst_m: string &optional;	##< The destination MAC address.
		redirect_port: count &optional;
	};

	## A rule for the framework to put in place. Of all rules currently in
	## place, the first match will be taken, sorted by priority. All
	## further rules will be ignored.
	type Rule: record {
		ty: RuleType;			##< Type of rule.
		target: TargetType;		##< Where to apply rule.
		entity: Entity;			##< Entity to apply rule to.
		expire: interval &optional;	##< Timeout after which to expire the rule.
		priority: int &default=default_priority;	##< Priority if multiple rules match an entity (larger value is higher priority).
		location: string &optional;	##< Optional string describing where/what installed the rule.

		out_port: count &optional;		##< Argument for :zeek:enum:`NetControl::REDIRECT` rules.
		mod: FlowMod &optional; ##< Argument for :zeek:enum:`NetControl::MODIFY` rules.

		id: string &default="";		##< Internally determined unique ID for this rule. Will be set when added.
		cid: count &default=0;		##< Internally determined unique numeric ID for this rule. Set when added.
	};

	## Information of a flow that can be provided by switches when the flow times out.
	## Currently this is heavily influenced by the data that OpenFlow returns by default.
	## That being said - their design makes sense and this is probably the data one
	## can expect to be available.
	type FlowInfo: record {
		duration: interval &optional; ##< Total duration of the rule.
		packet_count: count &optional; ##< Number of packets exchanged over connections matched by the rule.
		byte_count: count &optional; ##< Total bytes exchanged over connections matched by the rule.
	};
}
