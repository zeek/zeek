##! Add a field that logs the order of hosts sending messages
##! using the same DHCP transaction ID.  This information is
##! occasionally needed on some networks to fully explain the
##! DHCP sequence.

@load base/protocols/dhcp

module DHCP;

export {
	redef record DHCP::Info += {
		## The address that originated each message from the
		## `msg_types` field.
		msg_orig: vector of addr &log &default=addr_vec();
	};
}

event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=3
	{
	log_info$msg_orig += is_orig ? id$orig_h : id$resp_h;
	}
