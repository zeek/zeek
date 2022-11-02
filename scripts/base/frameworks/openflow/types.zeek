##! Types used by the OpenFlow framework.

module OpenFlow;

@load ./consts

export {
	## Available openflow plugins.
	type Plugin: enum {
		## Internal placeholder plugin.
		INVALID,
	};

	## Controller related state.
	## Can be redefined by plugins to
	## add state.
	type ControllerState: record {
		## Internally set to the type of plugin used.
		_plugin: Plugin &optional;
		## Internally set to the unique name of the controller.
		_name: string &optional;
		## Internally set to true once the controller is activated.
		_activated: bool &default=F;
	} &redef;

	## Openflow match definition.
	##
	## The openflow match record describes
	## which packets match to a specific
	## rule in a flow table.
	type ofp_match: record {
		# Input switch port.
		in_port: count &optional;
		# Ethernet source address.
		dl_src: string &optional;
		# Ethernet destination address.
		dl_dst: string &optional;
		# Input VLAN id.
		dl_vlan: count &optional;
		# Input VLAN priority.
		dl_vlan_pcp: count &optional;
		# Ethernet frame type.
		dl_type: count &optional;
		# IP ToS (actually DSCP field, 6bits).
		nw_tos: count &optional;
		# IP protocol or lower 8 bits of ARP opcode.
		nw_proto: count &optional;
		# At the moment, we store both v4 and v6 in the same fields.
		# This is not how OpenFlow does it, we might want to change that...
		# IP source address.
		nw_src: subnet &optional;
		# IP destination address.
		nw_dst: subnet &optional;
		# TCP/UDP source port.
		tp_src: count &optional;
		# TCP/UDP destination port.
		tp_dst: count &optional;
	} &log;

	## The actions that can be taken in a flow.
	## (Separate record to make ofp_flow_mod less crowded)
	type ofp_flow_action: record {
		## Output ports to send data to.
		out_ports: vector of count &default=vector();
		## Set vlan vid to this value.
		vlan_vid: count &optional;
		## Set vlan priority to this value.
		vlan_pcp: count &optional;
		## Strip vlan tag.
		vlan_strip: bool &default=F;
		## Set ethernet source address.
		dl_src: string &optional;
		## Set ethernet destination address.
		dl_dst: string &optional;
		## Set ip tos to this value.
		nw_tos: count &optional;
		## Set source to this ip.
		nw_src: addr &optional;
		## Set destination to this ip.
		nw_dst: addr &optional;
		## Set tcp/udp source port.
		tp_src: count &optional;
		## Set tcp/udp destination port.
		tp_dst: count &optional;
	} &log;

	## Openflow flow_mod definition, describing the action to perform.
	type ofp_flow_mod: record {
		## Opaque controller-issued identifier.
		# This is optional in the specification - but let's force
		# it so we always can identify our flows...
		cookie: count; # &default=ZEEK_COOKIE_ID * COOKIE_BID_START;
		# Flow actions
		## Table to put the flow in. OFPTT_ALL can be used for delete,
		## to delete flows from all matching tables.
		table_id: count &optional;
		## One of OFPFC_*.
		command: ofp_flow_mod_command; # &default=OFPFC_ADD;
		## Idle time before discarding (seconds).
		idle_timeout: count &default=0;
		## Max time before discarding (seconds).
		hard_timeout: count &default=0;
		## Priority level of flow entry.
		priority: count &default=0;
		## For OFPFC_DELETE* commands, require matching entry to include
		## this as an output port/group. OFPP_ANY/OFPG_ANY means no restrictions.
		out_port: count &optional;
		out_group: count &optional;
		## Bitmap of the OFPFF_* flags
		flags: count &default=0;
		## Actions to take on match
		actions: ofp_flow_action &default=ofp_flow_action();
	} &log;

	## Controller record representing an openflow controller.
	type Controller: record {
		## Controller related state.
		state: ControllerState;
		## Does the controller support the flow_removed event?
		supports_flow_removed: bool;
		## Function that describes the controller. Has to be implemented.
		describe: function(state: ControllerState): string;
		## One-time initialization function. If defined, controller_init_done has to be called once initialization finishes.
		init: function (state: ControllerState) &optional;
		## One-time destruction function.
		destroy: function (state: ControllerState) &optional;
		## flow_mod function.
		flow_mod: function(state: ControllerState, match: ofp_match, flow_mod: ofp_flow_mod): bool &optional;
		## flow_clear function.
		flow_clear: function(state: ControllerState): bool &optional;
	};
}
