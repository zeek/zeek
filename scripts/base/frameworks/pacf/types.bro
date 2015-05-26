
module Pacf;

export {
	## Type of a :bro:id:`Entity` for defining an action.
	type EntityType: enum {
		ADDRESS,	##< Activity involving a specific IP address.
		CONNECTION,	##< All of a bi-directional connection's activity.
		FLOW,		##< All of a uni-directional flow's activity. Can contain wildcards.
		MAC,		##< Activity involving a MAC address.
	};

	## Type of a :bro:id:`Flow` for defining a flow.
	type Flow: record {
		src_h: subnet &optional;	##< The source IP address/subnet.
		src_p: port &optional;	##< The source port number.
		dst_h: subnet &optional;	##< The destination IP address/subnet.
		dst_p: port &optional;	##< The desintation port number.
		src_m: string &optional;	##< The source MAC address.
		dst_m: string &optional;	##< The destination MAC address.
	};

	## Type defining the enity an :bro:id:`Rule` is operating on.
	type Entity: record {
		ty: EntityType;			##< Type of entity.
		conn: conn_id &optional;	##< Used with :bro:id:`CONNECTION` .
		flow: Flow &optional;	##< Used with :bro:id:`FLOW` .
		ip: subnet &optional;		##< Used with bro:id:`ADDRESS`; can specifiy a CIDR subnet.
		mac: string &optional;		##< Used with :bro:id:`MAC`.
	};

	## Target of :bro:id:`Rule` action.
	type TargetType: enum {
		FORWARD,	#< Apply rule actively to traffic on forwarding path.
		MONITOR,	#< Apply rule passively to traffic sent to Bro for monitoring.
	};

	## Type of rules that the framework supports. Each type lists the
	## :bro:id:`Rule` argument(s) it uses, if any.
	##
	## Plugins may extend this type to define their own.
	type RuleType: enum {
		## Stop forwarding all packets matching entity.
		##
		## No arguments.
		DROP,

		## Begin rate-limiting flows matching entity.
		##
		## d: Percent of available bandwidth.
		LIMIT,

		## Begin modifying all packets matching entity.
		##
		## .. todo::
		##	Define arguments.
		MODIFY,

		## Begin redirecting all packets matching entity.
		##
		## .. todo::
		##	c: output port to redirect traffic to.
		REDIRECT,

		## Begin sampling all flows matching entity.
		##
		## d: Probability to include a flow between 0 and 1.
		SAMPLE,

		## Whitelists all packets of an entity, meaning no restrictions will be applied.
		## While whitelisting is the default if no rule matches an this can type can be
		## used to override lower-priority rules that would otherwise take effect for the
		## entity.
		WHITELIST,
	};

	## Type of a :bro:id:`FlowMod` for defining a flow modification action.
	type FlowMod: record {
		src_h: addr &optional;	##< The source IP address.
		src_p: count &optional;	##< The source port number.
		dst_h: addr &optional;	##< The destination IP address.
		dst_p: count &optional;	##< The desintation port number.
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
		priority: int &default=+0;	##< Priority if multiple rules match an entity (larger value is higher priority).
		location: string &optional;	##< Optional string describing where/what installed the rule.

		c: count &optional;		##< Argument for rule types requiring an count argument.
		i: int &optional;		##< Argument for rule types requiring an integer argument.
		d: double &optional;		##< Argument for rule types requiring a double argument.
		s: string &optional;		##< Argument for rule types requiring a string argument.
		mod: FlowMod &optional; ##< Argument for :bro:id:`MODIFY` rules.

		id: count &default=0;		##< Internally determined unique ID for this rule. Will be set when added.
	};

	## Information of a flow that can be provided by switches when the flow times out.
	## Currently this is heavily influenced by the data that OpenFlow returns by default.
	## That being said - their design makes sense and this is probably the data one
	## can expect to be available.
	type FlowInfo: record {
		duration: interval &optional; ##< total duration of the rule
		packet_count: count &optional; ##< number of packets exchanged over connections matched by the rule
		byte_count: count &optional; ##< total bytes exchanged over connections matched by the rule
	};

	## Type of notifications that the framework supports. Each type lists the
	## :bro:id:`Notification` argument(s) it uses, if any. 
	##
	## Plugins may extend this type to define their own.
	type NotificationType: enum {
		## Notify if threshold of packets has been reached by entity.
		##
		## i: Number of packets.
		NUM_PACKETS,

		## Notify if threshold of bytes has been reached by entity.
		##
		## i: Number of bytes.
		NUM_BYTES,
	};

	## A notification for the framework to raise when a condition has been reached.
	## Different than with rules, all matching conditions will be reported, not only
	## the first match.
	type Notification: record {
		ty: NotificationType;			##< Type of notification.
		entity: Entity;			##< Entity to apply notification to.
		expire: interval &optional;	##< Timeout after which to expire the notification.
		src: string &optional;		##< Optional string describing where/what installed the notification.

		i: int;				##< Argument for notification types requiring an integer argument.
		d: double;			##< Argument for notification types requiring a double argument.
		s: string;			##< Argument for notification types requiring a string argument.

		id: count &default=0;		##< Internally determined unique ID for this notification. Will be set when added.
	};

}

