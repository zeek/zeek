connection DHCP_Conn(bro_analyzer: BroAnalyzer) {
	upflow = DHCP_Flow(true);
	downflow = DHCP_Flow(false);
};

flow DHCP_Flow(is_orig: bool) {
	datagram = DHCP_Message withcontext(connection, this);

	%member{
		BroVal dhcp_msg_val_;
	%}

	%init{
		dhcp_msg_val_ = 0;
	%}

	%cleanup{
		Unref(dhcp_msg_val_);
		dhcp_msg_val_ = 0;
	%}

	function get_dhcp_msgtype(options: DHCP_Option[]): uint8
		%{
		vector<DHCP_Option*>::const_iterator ptr;
		uint8 type = 0;

		// Leave the for loop if the message type is found.
		bool parsed = false;

		for ( ptr = options->begin();
		      ptr != options->end() && ! (*ptr)->last(); ++ptr )
			{
			// We use a switch for future expandability.
			switch ( (*ptr)->code() ) {
			case MSG_TYPE_OPTION:
				type = (*ptr)->info()->msg_type();
				parsed = true;
				break;
			}

			if ( parsed )
				break;
			}

		if ( type == 0 )
			connection()->bro_analyzer()->ProtocolViolation("no DHCP message type option");

		return type;
		%}

	function parse_request(options: DHCP_Option[], type: uint8): bool
		%{
		vector<DHCP_Option*>::const_iterator ptr;

		// Requested IP address to the server.
		::uint32 req_addr = 0, serv_addr = 0;
		StringVal* host_name = 0;

		for ( ptr = options->begin();  ptr != options->end() && ! (*ptr)->last(); ++ptr )
			{
			switch ( (*ptr)->code() )
				{
				case REQ_IP_OPTION:
					req_addr = htonl((*ptr)->info()->req_addr());
					break;

				case SERV_ID_OPTION:
					serv_addr = htonl((*ptr)->info()->serv_addr());
					break;

				case HOST_NAME_OPTION:
					Unref(host_name);
					host_name = new StringVal((*ptr)->info()->host_name().length(),
								  (const char*) (*ptr)->info()->host_name().begin());
					break;
				}
			}

		if ( host_name == 0 )
			host_name = new StringVal("");

		switch ( type )
			{
			case DHCPDISCOVER:
				BifEvent::generate_dhcp_discover(connection()->bro_analyzer(),
								 connection()->bro_analyzer()->Conn(),
								 dhcp_msg_val_->Ref(), new AddrVal(req_addr), host_name);
				break;

			case DHCPREQUEST:
				BifEvent::generate_dhcp_request(connection()->bro_analyzer(),
								connection()->bro_analyzer()->Conn(),
								dhcp_msg_val_->Ref(), new AddrVal(req_addr),
								new AddrVal(serv_addr), host_name);
				break;

			case DHCPDECLINE:
				BifEvent::generate_dhcp_decline(connection()->bro_analyzer(),
								connection()->bro_analyzer()->Conn(),
								dhcp_msg_val_->Ref(), host_name);
				break;

			case DHCPRELEASE:
				BifEvent::generate_dhcp_release(connection()->bro_analyzer(),
								connection()->bro_analyzer()->Conn(),
								dhcp_msg_val_->Ref(), host_name);
				break;

			case DHCPINFORM:
				BifEvent::generate_dhcp_inform(connection()->bro_analyzer(),
							       connection()->bro_analyzer()->Conn(),
							       dhcp_msg_val_->Ref(), host_name);
				break;

			default:
				Unref(host_name);
				break;
			}

		return true;
		%}

	function parse_reply(options: DHCP_Option[], type: uint8): bool
		%{
		vector<DHCP_Option*>::const_iterator ptr;

		// RFC 1533 allows a list of router addresses.
		TableVal* router_list = 0;

		::uint32 subnet_mask = 0, serv_addr = 0;

		uint32 lease = 0;
		StringVal* host_name = 0;

		for ( ptr = options->begin();
		      ptr != options->end() && ! (*ptr)->last(); ++ptr )
			{
			switch ( (*ptr)->code() )
				{
				case SUBNET_OPTION:
					subnet_mask = htonl((*ptr)->info()->mask());
					break;

				case ROUTER_OPTION:
					// Let's hope there aren't multiple
					// such options.
					Unref(router_list);
					router_list = new TableVal(dhcp_router_list);

						{
						int num_routers = (*ptr)->info()->router_list()->size();

						for ( int i = 0; i < num_routers; ++i )
							{
							vector<uint32>* rlist = (*ptr)->info()->router_list();

							uint32 raddr = (*rlist)[i];
							::uint32 tmp_addr;
							tmp_addr = htonl(raddr);

							// index starting from 1
							Val* index = new Val(i + 1, TYPE_COUNT);
							router_list->Assign(index, new AddrVal(tmp_addr));
							Unref(index);
							}
						}
					break;

				case LEASE_OPTION:
					lease = (*ptr)->info()->lease();
					break;

				case SERV_ID_OPTION:
					serv_addr = htonl((*ptr)->info()->serv_addr());
					break;

				case HOST_NAME_OPTION:
					Unref(host_name);
					host_name = new StringVal((*ptr)->info()->host_name().length(),
								  (const char*) (*ptr)->info()->host_name().begin());
					break;
				}
			}

			if ( host_name == 0 )
				host_name = new StringVal("");

		switch ( type )
			{
			case DHCPOFFER:
				BifEvent::generate_dhcp_offer(connection()->bro_analyzer(),
							      connection()->bro_analyzer()->Conn(),
							      dhcp_msg_val_->Ref(), new AddrVal(subnet_mask),
							      router_list, lease, new AddrVal(serv_addr), host_name);
				break;

			case DHCPACK:
				BifEvent::generate_dhcp_ack(connection()->bro_analyzer(),
							    connection()->bro_analyzer()->Conn(),
							    dhcp_msg_val_->Ref(), new AddrVal(subnet_mask),
							    router_list, lease, new AddrVal(serv_addr), host_name);
				break;

			case DHCPNAK:
				BifEvent::generate_dhcp_nak(connection()->bro_analyzer(),
							    connection()->bro_analyzer()->Conn(),
							    dhcp_msg_val_->Ref(), host_name);
				break;

			default:
				Unref(host_name);
				break;
			}

		return true;

		%}

	function process_dhcp_message(msg: DHCP_Message): bool
		%{
		// Check whether the options in the message conform to
		// DHCP or BOOTP.  If not, we are unable to interpret
		// the message options.
		if ( ${msg.cookie} != 0x63825363 )
			{
			connection()->bro_analyzer()->ProtocolViolation(fmt("bad cookie (%d)", ${msg.cookie}));
			return false;
			}

		Unref(dhcp_msg_val_);

		const char* mac_str = fmt_mac(${msg.chaddr}.data(), ${msg.chaddr}.length());

		RecordVal* r = new RecordVal(dhcp_msg);
		r->Assign(0, new Val(${msg.op}, TYPE_COUNT));
		r->Assign(1, new Val(${msg.type}, TYPE_COUNT));
		r->Assign(2, new Val(${msg.xid}, TYPE_COUNT));
		r->Assign(3, new StringVal(mac_str));
		r->Assign(4, new AddrVal(${msg.ciaddr}));
		r->Assign(5, new AddrVal(${msg.yiaddr}));

		delete [] mac_str;

		dhcp_msg_val_ = r;

		switch ( ${msg.op} )
			{
			case BOOTREQUEST:	// presumably from client to server
				if ( ${msg.type} == DHCPDISCOVER ||
			     	     ${msg.type} == DHCPREQUEST ||
			     	     ${msg.type} == DHCPDECLINE ||
			     	     ${msg.type} == DHCPRELEASE ||
			     	     ${msg.type} == DHCPINFORM )
					parse_request(${msg.options}, ${msg.type});
				else
					connection()->bro_analyzer()->ProtocolViolation(fmt("unknown DHCP message type option for BOOTREQUEST (%d)",
											    ${msg.type}));
				break;

			case BOOTREPLY:		// presumably from server to client
				if ( ${msg.type} == DHCPOFFER ||
			     	     ${msg.type} == DHCPACK ||
				     ${msg.type} == DHCPNAK )
					parse_reply(${msg.options}, ${msg.type});
				else
					connection()->bro_analyzer()->ProtocolViolation(fmt("unknown DHCP message type option for BOOTREPLY (%d)",
											    ${msg.type}));

				break;

			default:
				connection()->bro_analyzer()->ProtocolViolation(fmt("unknown DHCP message op code (%d). Known codes: 1=BOOTREQUEST, 2=BOOTREPLY",
										${msg.op}));
				break;
			}

		connection()->bro_analyzer()->ProtocolConfirmation();
		return true;
		%}
};

refine typeattr DHCP_Message += &let {
	proc_dhcp_message = $context.flow.process_dhcp_message(this);
};
