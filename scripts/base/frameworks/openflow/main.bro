@load ./utils/const.bro

module Openflow;

export {
# ofp_port: enum {
	# Maximum number of physical switch ports.
	const OFPP_MAX = 0xff00;
	########################
	# Fake output "ports". #
	########################
	# Send the packet out the input port. This
	# virual port must be explicitly used in 
	# order to send back out of the input port.
	const OFPP_IN_PORT = 0xfff8;
	# Perform actions in flow table.
	# NB: This can only be the destination port
	# for packet-out messages.
	const OFPP_TABLE = 0xfff9;
	# Process with normal L2/L3 switching.
	const OFPP_NORMAL = 0xfffa;
	# All pysical ports except input port and
	# those disabled by STP.
	const OFPP_FLOOD = 0xfffb;
	# All pysical ports except input port.
	const OFPP_ALL = 0xfffc;
	# Send to controller.
	const OFPP_CONTROLLER = 0xfffd;
	# Local openflow "port".
	const OFPP_LOCAL = 0xfffe;
	# Not associated with a pysical port.
	const OFPP_NONE = 0xffff;
# }
	type ofp_action_type: enum {
		# Output to switch port.
		OFPAT_OUTPUT = 0x0000,
		# Set the 802.1q VLAN id.
		OFPAT_SET_VLAN_VID = 0x0001,
		# Set the 802.1q priority.
		OFPAT_SET_VLAN_PCP = 0x0002,
		# Strip the 802.1q header.
		OFPAT_STRIP_VLAN = 0x0003,
		# Ethernet source address.
		OFPAT_SET_DL_SRC = 0x0004,
		# Ethernet destination address.
		OFPAT_SET_DL_DST = 0x0005,
		# IP source address
		OFPAT_SET_NW_SRC = 0x0006,
		# IP destination address.
		OFPAT_SET_NW_DST = 0x0007,
		# IP ToS (DSCP field, 6 bits).
		OFPAT_SET_NW_TOS = 0x0008,
		# TCP/UDP source port.
		OFPAT_SET_TP_SRC = 0x0009,
		# TCP/UDP destination port.
		OFPAT_SET_TP_DST = 0x000a,
		# Output to queue.
		OFPAT_ENQUEUE = 0x000b,
		OFPAT_VENDOR = 0xffff,
	};

	type ofp_flow_mod_command: enum {
		# New flow.
		OFPFC_ADD,
		# Modify all matching flows.
		OFPFC_MODIFY,
		# Modify entry strictly matching wildcards.
		OFPFC_MODIFY_STRICT,
		# Delete all matching flows.
		OFPFC_DELETE,
		# Strictly matching wildcards and priority.
		OFPFC_DELETE_STRICT,
	};

	type ofp_config_flags: enum {
		# No special handling for fragments.
		OFPC_FRAG_NORMAL = 0,
		# Drop fragments.
		OFPC_FRAG_DROP = 1,
		# Reassemble (only if OFPC_IP_REASM set).
		OFPC_FRAG_REASM = 2,
		OFPC_FRAG_MASK = 3,
	};
	
	type ofp_match: record {
		# Wildcard fields.
		#wildcards: count &optional;
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
		dl_type: count &default=ETH_IPv4;
		# IP ToS (actually DSCP field, 6bits).
		nw_tos: count &optional;
		# IP protocol or lower 8 bits of ARP opcode.
		nw_proto: count &default=IP_TCP;
		# IP source address.
		nw_src: addr &optional;
		# IP destination address.
		nw_dst: addr &optional;
		# TCP/UDP source port.
		tp_src: port &optional;
		# TCP/UDP destination port.
		tp_dst: port &optional;
	};

	type ofp_action_output: record {
		# this should never change, but there are not
		# constants available in records
		# defaults to OFPAT_OUTPUT
		_type: ofp_action_type &default=OFPAT_OUTPUT;
		#_len: count &default=8;
		# Output port.
		_port: count &default=OFPP_FLOOD;
		#_max_len: count &optional;
	};

#type ofp_flow_mod_flags:  enum {
	# Send flow removed message when flow
	# expires or is deleted.
	const OFPFF_SEND_FLOW_REM = 0x1;
	# Check for overlapping entries first.
	const OFPFF_CHECK_OVERLAP = 0x2;
	# Remark this is for emergency.
	# Flows added with this are only used
	# when the controller is disconnected.
	const OFPFF_EMERG = 0x4;
#};

	type ofp_flow_mod: record {
		# header: ofp_header;
		# Fields to match
		match: ofp_match;
		# Opaque controller-issued identifier.
		cookie: count &optional;

		# Flow actions

		# One of OFPFC_*.
		command: ofp_flow_mod_command &default=OFPFC_ADD;
		# Idle time befor discarding (seconds).
		idle_timeout: count &optional;
		# Max time before discarding (seconds).
		hard_timeout: count &optional;
		# Priority level of flow entry.
		priority: count &optional;
		# Buffered packet to apply to (or -1).
		# Not meaningful for OFPFC_DELETE*.
		buffer_id: count &optional;
		# For OFPFC_DELETE* commands, require
		# matching entries to include this as an
		# output port. A value of OFPP_NONE
		# indicates no restrictions
		out_port: count &optional;
		# One of OFPFF_*.
		flags: count &optional;
		actions: vector of ofp_action_output;
	};

	global flow_mod: function(dpid: count, flow_mod: ofp_flow_mod): bool;
}

# Flow Modification function prototype
type FlowModFunc: function(dpid: count, flow_mod: ofp_flow_mod): bool;

# Flow Modification function
global FlowMod: FlowModFunc;

# Hook for registering openflow plugins
global register_openflow_plugin: hook();

function register_openflow_mod_func(func: FlowModFunc) {
	FlowMod = func;
}

function flow_mod(dpid: count, flow_mod: ofp_flow_mod): bool {
	return FlowMod(dpid, flow_mod);
}

event bro_init() &priority=100000 {
	# Call all of the plugin registration hooks
	hook register_openflow_plugin();
}
