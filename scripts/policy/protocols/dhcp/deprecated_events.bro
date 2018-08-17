##! Bro 2.6 removed certain DHCP events, but scripts in the Bro
##! ecosystem are still relying on those events. As a transition, this
##! script will handle the new event, and generate the old events,
##! which are marked as deprecated.  Note: This script should be
##! removed in the next Bro version after 2.6.

@load base/protocols/dhcp

## A DHCP message.
##
## .. note:: This type is included to support the deprecated events dhcp_ack,
##           dhcp_decline, dhcp_discover, dhcp_inform, dhcp_nak, dhcp_offer,
##           dhcp_release and dhcp_request and is thus similarly deprecated
##           itself. Use :bro:see:`dhcp_message` instead.
##
## .. bro:see:: dhcp_message dhcp_ack dhcp_decline dhcp_discover
##              dhcp_inform dhcp_nak dhcp_offer dhcp_release dhcp_request
type dhcp_msg: record {
	op: count;      ##< Message OP code. 1 = BOOTREQUEST, 2 = BOOTREPLY
	m_type: count;  ##< The type of DHCP message.
	xid: count;     ##< Transaction ID of a DHCP session.
	h_addr: string; ##< Hardware address of the client.
	ciaddr: addr;   ##< Original IP address of the client.
	yiaddr: addr;   ##< IP address assigned to the client.
};

## A list of router addresses offered by a DHCP server.
##
## .. note:: This type is included to support the deprecated events dhcp_ack
##           and dhcp_offer and is thus similarly deprecated
##           itself. Use :bro:see:`dhcp_message` instead.
##
## .. bro:see:: dhcp_message dhcp_ack dhcp_offer
type dhcp_router_list: table[count] of addr;

## Generated for DHCP messages of type *DHCPDISCOVER* (client broadcast to locate
## available servers).
##
## c: The connection record describing the underlying UDP flow.
##
## msg: The parsed type-independent part of the DHCP message.
##
## req_addr: The specific address requested by the client.
##
## host_name: The value of the host name option, if specified by the client.
##
## .. bro:see:: dhcp_message dhcp_discover dhcp_offer dhcp_request
##              dhcp_decline dhcp_ack dhcp_nak dhcp_release dhcp_inform
##
## .. note:: This event has been deprecated, and will be removed in the next version.
##    Use dhcp_message instead.
##
## .. note:: Bro does not support broadcast packets (as used by the DHCP
##    protocol). It treats broadcast addresses just like any other and
##    associates packets into transport-level flows in the same way as usual.
##
global dhcp_discover: event(c: connection, msg: dhcp_msg, req_addr: addr, host_name: string) &deprecated;

## Generated for DHCP messages of type *DHCPOFFER* (server to client in response
## to DHCPDISCOVER with offer of configuration parameters).
##
## c: The connection record describing the underlying UDP flow.
##
## msg: The parsed type-independent part of the DHCP message.
##
## mask: The subnet mask specified by the message.
##
## router: The list of routers specified by the message.
##
## lease: The least interval specified by the message.
##
## serv_addr: The server address specified by the message.
##
## host_name: Optional host name value. May differ from the host name requested
##            from the client.
##
## .. bro:see:: dhcp_message dhcp_discover dhcp_request dhcp_decline
##              dhcp_ack dhcp_nak dhcp_release dhcp_inform
##
## .. note:: This event has been deprecated, and will be removed in the next version.
##    Use dhcp_message instead.
##
## .. note:: Bro does not support broadcast packets (as used by the DHCP
##    protocol). It treats broadcast addresses just like any other and
##    associates packets into transport-level flows in the same way as usual.
##
global dhcp_offer: event(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string) &deprecated;

## Generated for DHCP messages of type *DHCPREQUEST* (Client message to servers either
## (a) requesting offered parameters from one server and implicitly declining offers
## from all others, (b) confirming correctness of previously allocated address after,
## e.g., system reboot, or (c) extending the lease on a particular network address.)
##
## c: The connection record describing the underlying UDP flow.
##
## msg: The parsed type-independent part of the DHCP message.
##
## req_addr: The client address specified by the message.
##
## serv_addr: The server address specified by the message.
##
## host_name: The value of the host name option, if specified by the client.
##
## .. bro:see:: dhcp_message dhcp_discover dhcp_offer dhcp_decline
##    	       dhcp_ack dhcp_nak dhcp_release dhcp_inform
##
## .. note:: This event has been deprecated, and will be removed in the next version.
##    Use dhcp_message instead.
##
## .. note:: Bro does not support broadcast packets (as used by the DHCP
##    protocol). It treats broadcast addresses just like any other and
##    associates packets into transport-level flows in the same way as usual.
##
global dhcp_request: event(c: connection, msg: dhcp_msg, req_addr: addr, serv_addr: addr, host_name: string) &deprecated;

## Generated for DHCP messages of type *DHCPDECLINE* (Client to server indicating
## network address is already in use).
##
## c: The connection record describing the underlying UDP flow.
##
## msg: The parsed type-independent part of the DHCP message.
##
## host_name: Optional host name value.
##
## .. bro:see:: dhcp_message dhcp_discover dhcp_offer dhcp_request
##              dhcp_ack dhcp_nak dhcp_release dhcp_inform
##
## .. note:: This event has been deprecated, and will be removed in the next version.
##    Use dhcp_message instead.
##
## .. note:: Bro does not support broadcast packets (as used by the DHCP
##    protocol). It treats broadcast addresses just like any other and
##    associates packets into transport-level flows in the same way as usual.
##
global dhcp_decline: event(c: connection, msg: dhcp_msg, host_name: string) &deprecated;

## Generated for DHCP messages of type *DHCPACK* (Server to client with configuration
## parameters, including committed network address).
##
## c: The connection record describing the underlying UDP flow.
##
## msg: The parsed type-independent part of the DHCP message.
##
## mask: The subnet mask specified by the message.
##
## router: The list of routers specified by the message.
##
## lease: The least interval specified by the message.
##
## serv_addr: The server address specified by the message.
##
## host_name: Optional host name value. May differ from the host name requested
##            from the client.
##
## .. bro:see:: dhcp_message dhcp_discover dhcp_offer dhcp_request
##              dhcp_decline dhcp_nak dhcp_release dhcp_inform
##
## .. note:: This event has been deprecated, and will be removed in the next version.
##    Use dhcp_message instead.
##
global dhcp_ack: event(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string) &deprecated;

## Generated for DHCP messages of type *DHCPNAK* (Server to client indicating client's
## notion of network address is incorrect (e.g., client has moved to new subnet) or
## client's lease has expired).
##
## c: The connection record describing the underlying UDP flow.
##
## msg: The parsed type-independent part of the DHCP message.
##
## host_name: Optional host name value.
##
## .. bro:see:: dhcp_message dhcp_discover dhcp_offer dhcp_request
##              dhcp_decline dhcp_ack dhcp_release dhcp_inform
##
## .. note:: This event has been deprecated, and will be removed in the next version.
##    Use dhcp_message instead.
##
## .. note:: Bro does not support broadcast packets (as used by the DHCP
##    protocol). It treats broadcast addresses just like any other and
##    associates packets into transport-level flows in the same way as usual.
##
global dhcp_nak: event(c: connection, msg: dhcp_msg, host_name: string) &deprecated;

## Generated for DHCP messages of type *DHCPRELEASE* (Client to server relinquishing
## network address and cancelling remaining lease).
##
## c: The connection record describing the underlying UDP flow.
##
## msg: The parsed type-independent part of the DHCP message.
##
## host_name: The value of the host name option, if specified by the client.
##
## .. bro:see:: dhcp_message dhcp_discover dhcp_offer dhcp_request
##              dhcp_decline dhcp_ack dhcp_nak dhcp_inform
##
## .. note:: This event has been deprecated, and will be removed in the next version.
##    Use dhcp_message instead.
##
global dhcp_release: event(c: connection, msg: dhcp_msg, host_name: string) &deprecated;

## Generated for DHCP messages of type *DHCPINFORM* (Client to server, asking only for
## local configuration parameters; client already has externally configured network
## address).
##
## c: The connection record describing the underlying UDP flow.
##
## msg: The parsed type-independent part of the DHCP message.
##
## host_name: The value of the host name option, if specified by the client.
##
## .. bro:see:: dhcp_message dhcp_discover dhcp_offer dhcp_request
##              dhcp_decline dhcp_ack dhcp_nak dhcp_release
##
## .. note:: This event has been deprecated, and will be removed in the next version.
##    Use dhcp_message instead.
##
## .. note:: Bro does not support broadcast packets (as used by the DHCP
##    protocol). It treats broadcast addresses just like any other and
##    associates packets into transport-level flows in the same way as usual.
##
global dhcp_inform: event(c: connection, msg: dhcp_msg, host_name: string) &deprecated;

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
	{
	local old_msg: dhcp_msg = [$op=msg$op, $m_type=msg$m_type, $xid=msg$xid,
	                           $h_addr=msg$chaddr, $ciaddr=msg$ciaddr, $yiaddr=msg$yiaddr];

	local routers = dhcp_router_list();

	if ( options?$routers )
		for ( i in options$routers )
			routers[|routers|] = options$routers[i];

	# These fields are technically optional, but aren't listed as such in the event.
	# We give it some defaults in order to suppress errors.
	local ar = ( options?$addr_request ) ? options$addr_request : 0.0.0.0;
	local hn = ( options?$host_name ) ? options$host_name : "";
	local le = ( options?$lease ) ? options$lease : 0 secs;
	local sm = ( options?$subnet_mask ) ? options$subnet_mask : 255.255.255.255;
	local sa = ( options?$serv_addr ) ? options$serv_addr : 0.0.0.0;

	switch ( DHCP::message_types[msg$m_type] ) {
	case "DISCOVER":
		event dhcp_discover(c, old_msg, ar, hn);
		break;
	case "OFFER":
		event dhcp_offer(c, old_msg, sm, routers, le, sa, hn);
		break;
	case "REQUEST":
		event dhcp_request(c, old_msg, ar, sa, hn);
		break;
	case "DECLINE":
		event dhcp_decline(c, old_msg, hn);
		break;
	case "ACK":
		event dhcp_ack(c, old_msg, sm, routers, le, sa, hn);
		break;
	case "NAK":
		event dhcp_nak(c, old_msg, hn);
		break;
	case "RELEASE":
		event dhcp_release(c, old_msg, hn);
		break;
	case "INFORM":
		event dhcp_inform(c, old_msg, hn);
		break;
	default:
		# This isn't a weird, it's just a DHCP message type the old scripts don't handle
		break;
		}
	}
