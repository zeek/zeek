
@load base/protocols/dhcp

module DHCP;

export {
	redef record DHCP::Info += {
		## Added by DHCP relay agents which terminate switched or
		## permanent circuits.  It encodes an agent-local identifier
		## of the circuit from which a DHCP client-to-server packet was
		## received.  Typically it should represent a router or switch
		## interface number.
		circuit_id:      string &log &optional;

		## A globally unique identifier added by relay agents to identify
		## the remote host end of the circuit.
		agent_remote_id: string &log &optional;

		## The subscriber ID is a value independent of the physical
		## network configuration so that a customer's DHCP configuration
		## can be given to them correctly no matter where they are
		## physically connected.
		subscriber_id:   string &log &optional;
	};
}

event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
	{
	if ( options?$sub_opt )
		{
		for ( i in options$sub_opt )
			{
			local sub_opt = options$sub_opt[i];

			if ( sub_opt$code == 1 )
				DHCP::log_info$circuit_id = sub_opt$value;

			else if ( sub_opt$code == 2 )
				DHCP::log_info$agent_remote_id = sub_opt$value;

			else if ( sub_opt$code == 6 )
				DHCP::log_info$subscriber_id = sub_opt$value;
			}
		}
	}
