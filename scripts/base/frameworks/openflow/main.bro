@load ./utils/const.bro


module Openflow;


# Some cookie specific constants.
# first 24 bits
const COOKIE_BID_SIZE = 16777216;
# start at bit 40 (1 << 40)
const COOKIE_BID_START = 1099511627776;
# bro specific cookie ID shall have the 42 bit set (1 << 42)
const BRO_COOKIE_ID = 4;
# 8 bits group identifier
const COOKIE_GID_SIZE = 256;
# start at bit 32 (1 << 32)
const COOKIE_GID_START = 4294967296;
# 32 bits unique identifier
const COOKIE_UID_SIZE = 4294967296;
# start at bit 0 (1 << 0)
const COOKIE_UID_START = 0;


export {
	## Return value for a cookie from a flow
	## which is not added, modified or deleted
	## from the bro openflow framework
	const INVALID_COOKIE = 0xffffffffffffffff;

	# Openflow pysical port definitions
	## Maximum number of physical switch ports.
	const OFPP_MAX = 0xff00;
	## Send the packet out the input port. This
	## virual port must be explicitly used in
	## order to send back out of the input port.
	const OFPP_IN_PORT = 0xfff8;
	## Perform actions in flow table.
	## NB: This can only be the destination port
	## for packet-out messages.
	const OFPP_TABLE = 0xfff9;
	## Process with normal L2/L3 switching.
	const OFPP_NORMAL = 0xfffa;
	## All pysical ports except input port and
	## those disabled by STP.
	const OFPP_FLOOD = 0xfffb;
	## All pysical ports except input port.
	const OFPP_ALL = 0xfffc;
	## Send to controller.
	const OFPP_CONTROLLER = 0xfffd;
	## Local openflow "port".
	const OFPP_LOCAL = 0xfffe;
	## Not associated with a pysical port.
	const OFPP_NONE = 0xffff;

	## Openflow action_type definitions
	##
	## The openflow action type defines
	## what actions openflow can take
	## to modify a packet
	type ofp_action_type: enum {
		## Output to switch port.
		OFPAT_OUTPUT = 0x0000,
		## Set the 802.1q VLAN id.
		OFPAT_SET_VLAN_VID = 0x0001,
		## Set the 802.1q priority.
		OFPAT_SET_VLAN_PCP = 0x0002,
		## Strip the 802.1q header.
		OFPAT_STRIP_VLAN = 0x0003,
		## Ethernet source address.
		OFPAT_SET_DL_SRC = 0x0004,
		## Ethernet destination address.
		OFPAT_SET_DL_DST = 0x0005,
		## IP source address
		OFPAT_SET_NW_SRC = 0x0006,
		## IP destination address.
		OFPAT_SET_NW_DST = 0x0007,
		## IP ToS (DSCP field, 6 bits).
		OFPAT_SET_NW_TOS = 0x0008,
		## TCP/UDP source port.
		OFPAT_SET_TP_SRC = 0x0009,
		## TCP/UDP destination port.
		OFPAT_SET_TP_DST = 0x000a,
		## Output to queue.
		OFPAT_ENQUEUE = 0x000b,
		## Vendor specific
		OFPAT_VENDOR = 0xffff,
	};

	## Openflow flow_mod_command definitions
	##
	## The openflow flow_mod_command describes
	## of what kind an action is.
	type ofp_flow_mod_command: enum {
		## New flow.
		OFPFC_ADD = 0x0,
		## Modify all matching flows.
		OFPFC_MODIFY = 0x1,
		## Modify entry strictly matching wildcards.
		OFPFC_MODIFY_STRICT = 0x2,
		## Delete all matching flows.
		OFPFC_DELETE = 0x3,
		## Strictly matching wildcards and priority.
		OFPFC_DELETE_STRICT = 0x4,
	};

	## Openflow config flag definitions
	##
	## TODO: describe
	type ofp_config_flags: enum {
		## No special handling for fragments.
		OFPC_FRAG_NORMAL = 0,
		## Drop fragments.
		OFPC_FRAG_DROP = 1,
		## Reassemble (only if OFPC_IP_REASM set).
		OFPC_FRAG_REASM = 2,
		OFPC_FRAG_MASK = 3,
	};

	## Openflow match definition.
	##
	## The openflow match record describes
	## which packets match to a specific
	## rule in a flow table.
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

	## Openflow actions definition.
	##
	## A action describes what should
	## happen with packets of the matching
	## flow.
	type ofp_action_output: record {
		## this should never change, but there are not
		## constants available in records
		## defaults to OFPAT_OUTPUT
		type_: ofp_action_type &default=OFPAT_OUTPUT;
		#_len: count &default=8;
		## Output port.
		port_: count &default=OFPP_FLOOD;
		#_max_len: count &optional;
	};

	# Openflow flow_mod_flags definition
	## Send flow removed message when flow
	## expires or is deleted.
	const OFPFF_SEND_FLOW_REM = 0x1;
	## Check for overlapping entries first.
	const OFPFF_CHECK_OVERLAP = 0x2;
	## Remark this is for emergency.
	## Flows added with this are only used
	## when the controller is disconnected.
	const OFPFF_EMERG = 0x4;

	## Openflow flow_mod definition.
	## It describes the flow to match and
	## how it should be modified.
	type ofp_flow_mod: record {
		# header: ofp_header;
		## Fields to match
		match: ofp_match;
		## Opaque controller-issued identifier.
		cookie: count &default=BRO_COOKIE_ID * COOKIE_BID_START;
		# Flow actions
		## One of OFPFC_*.
		command: ofp_flow_mod_command &default=OFPFC_ADD;
		## Idle time befor discarding (seconds).
		idle_timeout: count &optional;
		## Max time before discarding (seconds).
		hard_timeout: count &optional;
		## Priority level of flow entry.
		priority: count &optional;
		## Buffered packet to apply to (or -1).
		## Not meaningful for OFPFC_DELETE*.
		buffer_id: count &optional;
		## For OFPFC_DELETE* commands, require
		## matching entries to include this as an
		## output port. A value of OFPP_NONE
		## indicates no restrictions.
		out_port: count &optional;
		## One of OFPFF_*.
		flags: count &optional;
		## A list of actions to perform.
		actions: vector of ofp_action_output;
	};

	## Body of reply to OFPST_FLOW request.
	type ofp_flow_stats: record {
		## Length of this entry
		_length: count;
		## ID of table flow came from.
		table_id: count;
		## Description of fields.
		match: ofp_match;
		## Time flow has been alive in seconds.
		duration_sec: count;
		## Time flow has been alive in nanoseconds beyond
		## duration_sec.
		duration_nsec: count;
		## Priority of the entry. Only meaningful
		## when this is not an exact-match entry.
		priority: count;
		## Number of seconds idle before expiration.
		idle_timeout: count;
		## Number of seconds before expiration.
		hard_timeout: count;
		## Opaque controller-issued identifier.
		cookie: count;
		## Number of packets in flow.
		packet_count: count;
		## Number of bytes in flow.
		byte_count: count;
		## Actions
		actions: vector of ofp_action_output;
	};

	## Function to get the unique id out of a given cookie.
	##
	## cookie: The openflow match cookie.
	##
	## Returns: The cookie unique id.
	global get_cookie_uid: function(cookie: count): count;

	## Function to get the group id out of a given cookie.
	##
	## cookie: The openflow match cookie.
	##
	## Returns: The cookie group id.
	global get_cookie_gid: function(cookie: count): count;

	## Function to get the group id out of a given cookie.
	##
	## cookie: The openflow match cookie.
	##
	## Returns: The cookie group id.
	global generate_cookie: function(cookie: count &default=0): count;

	## Event to signal that a flow has been successfully modified.
	##
	## flow_mod: The openflow flow_mod record which describes
	##           the flow to delete, modify or add.
	##
	## msg: Message to describe the event.
	global Openflow::flow_mod_success: event(flow_mod: ofp_flow_mod, msg: string &default="Flow successfully modified");

	## Event to signal that a flow mod has failed.
	##
	## flow_mod: The openflow flow_mod record which describes
	##           the flow to delete, modify or add.
	##
	## msg: Message to describe the event.
	global Openflow::flow_mod_failure: event(flow_mod: ofp_flow_mod, msg: string &default="Could not modify flow");

	## Available openflow plugins
	type Plugin: enum {
		PLACEHOLDER,
	};

	## Controller related state.
	## Can be redefined by plugins to
	## add state.
	type ControllerState: record {
		## Controller ip.
		ip: addr &optional;
		## Controller listen port.
		port_: count &optional;
		## Openflow switch datapath id.
		dpid: count &optional;
		## Type of the openflow plugin.
		type_: Plugin;
	} &redef;

	## Controller record representing an openflow controller
	type Controller: record {
		## Controller related state.
		state: ControllerState;
		## flow_mod function the plugin implements
		flow_mod: function(state: ControllerState, flow_mod: ofp_flow_mod): bool;
		## flow_stats function the plugin implements if existing 
		flow_stats: function(state: ControllerState): vector of ofp_flow_stats &optional;
	};

	## Global flow_mod function wrapper
	##
	## controller: The controller which should execute the flow modification
	##
	## flow_mod: The openflow flow_mod record which describes
	##           the flow to delete, modify or add
	##
	## Returns: T if successfull, else F
	global flow_mod: function(controller: Controller, flow_mod: ofp_flow_mod): bool;
}

# the flow_mod function wrapper
function flow_mod(controller: Controller, flow_mod: ofp_flow_mod): bool
	{
		return controller$flow_mod(controller$state, flow_mod);
	}


# local function to forge a flow_mod cookie for this framework.
# all flow entries from the openflow framework should have the
# 42 bit of the cookie set.
function generate_cookie(cookie: count &default=0): count
	{
	local c = BRO_COOKIE_ID * COOKIE_BID_START;
	if(cookie >= COOKIE_UID_SIZE)
		Reporter::warning(fmt("The given cookie uid '%d' is > 32bit and will be discarded", cookie));
	else
		c += cookie;
	return c;
	}


# local function to check if a given flow_mod cookie is forged from this framework.
function _is_valid_cookie(cookie: count): bool
	{
	if (cookie / COOKIE_BID_START == BRO_COOKIE_ID)
		return T;
	Reporter::warning(fmt("The given Openflow cookie '%d' is not valid", cookie));
	return F;
	}


function get_cookie_uid(cookie: count): count
	{
	if(_is_valid_cookie(cookie))
		return (cookie - ((cookie / COOKIE_GID_START) * COOKIE_GID_START));
	return INVALID_COOKIE;
	}


function get_cookie_gid(cookie: count): count
	{
	if(_is_valid_cookie(cookie))
		return (
			(cookie	- (COOKIE_BID_START * BRO_COOKIE_ID) - 
			(cookie - ((cookie / COOKIE_GID_START) * COOKIE_GID_START))) /
			COOKIE_GID_START
		);
	return INVALID_COOKIE;
	}
