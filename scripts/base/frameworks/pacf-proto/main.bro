@load ./plugins


module PACF;


# Internal id counter for rule ids.
global LAST_ID:count = 0;


export {
	
	## Type of the action.
	##
	type RuleActionType: enum {
		## Drop packets matching a given RuleMatch record.
		DROP,
		## Modify packets matching a given RuleMatch record
		## according to the ModifyArgs record.
		MODIFY,
	} &redef;


	type RuleActionTarget: enum {
		FORWARD,
		MONITOR,
	} &redef;

	## Uni or bidriectional flow.
	##
	type FlowType: enum {
		## Unidirectional flow.
		PACF::UNIDIRECTIONAL,
		## Bidirectional flow.
		PACF::BIDIRECTIONAL,
	};

	## Properties which descibes a matching flow / connection
	##
	type RuleMatch: record {
		## Ethernet protocol (ipv4, ipv6, ipip ... aso).
		# eth_proto: ethernet_proto &optional;  # Here should mb IPPROTO_* be used.
		## VLAN id.
		vlan: count &optional; 
		## Source MAC address.
		src_mac: string &optional;
		## Source IP address (IPv4 | IPv6).
		src_ip: addr &optional;
		## Source Port.
		src_port: port &optional;
		## Destination MAC address.
		dst_mac: string &optional;
		## Destination IP address.
		dst_ip: addr &optional;
		## Destination Port.
		dst_port: port &optional;
		## IP transport protocol.
		ip_proto: transport_proto &optional;  # Here should mb IPPROTO_* be used.
	};

	## Action to be done on flows / connections that match.
	##
	type RuleAction: record {
		type_: RuleActionType;
		target: RuleActionTarget &default=FORWARD;
		## Timeout n seconds after the last packet.
		soft_timeout: count &optional;
		## Timeout after n seconds.
		hard_timeout: count &optional;
		## Priority of the action.
		priority: int &default=-0;
	};

	## Rule which descibes the actions to take on a matching
	## flow / connection.
	type Rule: record {
		## Rule id.
		id: count &default=LAST_ID;
		## Flows / Connections which the rule should match.
		match: RuleMatch;
		## Actions which will be taken when a flow / connection matches.
		action: vector of RuleAction;
		## Should it be matched uni or bidriectional.
		direction: FlowType;
	};

	## Registered plugins
	type Plugin: enum {
	};


	type BackendState: record {

	} &redef;


	## A PACF backend which implements a subset of the PACF
	## features for a specific implementation
	type Backend: record {
		## The type of the plugin (more then one of the same type can exist).
		type_: Plugin;
		## Insert function to apply a specific rule
		insert: function(state: PACF::BackendState, rule: PACF::Rule): bool &optional;
		## Remove function to remove a specific rule
		remove: function(id: count): bool &optional;
		state: BackendState &optional;
	} &redef;

	global PACF::drop: event();
	global PACF::undrop: event();
}
