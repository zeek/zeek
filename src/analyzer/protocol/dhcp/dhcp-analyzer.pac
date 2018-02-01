connection DHCP_Conn(bro_analyzer: BroAnalyzer) {
	upflow = DHCP_Flow(true);
	downflow = DHCP_Flow(false);
};

flow DHCP_Flow(is_orig: bool) {
	datagram = DHCP_Message withcontext(connection, this);

	%member{
		BroVal dhcp_msg_val_;
		uint8 sum_len;
	%}

	%init{
		dhcp_msg_val_ = 0;
		sum_len = 0;
	%}

	%cleanup{
		Unref(dhcp_msg_val_);
		dhcp_msg_val_ = 0;
		sum_len = 0;
	%}

	function get_dhcp_sumlen(len: uint8): uint8
		%{
			sum_len = len + sum_len;
			return sum_len;
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
		StringVal* host_name = new StringVal("");

		TableVal* params_list = 0;
		RecordVal* client_id = new RecordVal(BifType::Record::DHCP::dhcp_client_id);
		client_id->Assign(0,0);
		client_id->Assign(1,new StringVal(""));

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
					host_name = new StringVal((*ptr)->info()->host_name().length(),
								  (const char*) (*ptr)->info()->host_name().begin());
					break;
				case CLIENT_ID_OPTION:
					client_id->Assign(0, new Val((*ptr)->info()->client_id()->hwtype(), TYPE_COUNT));
					client_id->Assign(1, new StringVal(fmt_mac((*ptr)->info()->client_id()->hwaddr().begin(), (*ptr)->info()->client_id()->hwaddr().length())));
					break;
				case PAR_REQ_LIST:
					params_list = new TableVal(BifType::Table::DHCP::dhcp_params_list);
					int num_parms = (*ptr)->info()->par_req_list()->size();
					for (int i=0; i < num_parms; ++i)
					{
						vector<uint8>* plist = (*ptr)->info()->par_req_list();
						uint8 param = (*plist)[i];
						Val* index = new Val(i+1, TYPE_COUNT);
						params_list->Assign(index, new Val(param, TYPE_COUNT));
						Unref(index);
					}
				break;
				}
			}

		switch ( type )
			{
			case DHCPDISCOVER:
				BifEvent::generate_dhcp_discover(connection()->bro_analyzer(),
								 connection()->bro_analyzer()->Conn(),
								 dhcp_msg_val_->Ref(), new AddrVal(req_addr),
								 host_name, client_id, params_list);
				break;

			case DHCPREQUEST:
				BifEvent::generate_dhcp_request(connection()->bro_analyzer(),
								connection()->bro_analyzer()->Conn(),
								dhcp_msg_val_->Ref(), new AddrVal(req_addr),
								new AddrVal(serv_addr), host_name, client_id, params_list);
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
							       dhcp_msg_val_->Ref(), host_name, params_list);
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
		vector<Relay_Agent_SubOption*>::const_iterator ptrsubopt;

		// RFC 1533 allows a list of router addresses.
		TableVal* router_list = 0;

		::uint32 subnet_mask = 0, serv_addr = 0;

		uint32 lease = 0;
		StringVal* host_name = 0;

		uint32 reb_time = 0;
		uint32 ren_time = 0;
		StringVal* agent_cir = 0;
		StringVal* agent_rem = 0;
		StringVal* agent_sub_opt = 0;
		TableVal* relay_agent_sub_opt = new TableVal(BifType::Table::DHCP::dhcp_sub_opt_list);

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
					//Unref(router_list);
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
					host_name = new StringVal((*ptr)->info()->host_name().length(),
								  (const char*) (*ptr)->info()->host_name().begin());
					break;

				case REB_TIME_OPTION:
					reb_time = (*ptr)->info()->reb_time();
					break;

				case REN_TIME_OPTION:
					ren_time = (*ptr)->info()->ren_time();
					break;

				case RELAY_AGENT_INF:
					RecordVal* r = new RecordVal(BifType::Record::DHCP::dhcp_sub_opt);
					uint i = 0;
					for( ptrsubopt = (*ptr)->info()->relay_agent_inf()->begin(); ptrsubopt != (*ptr)->info()->relay_agent_inf()->end(); ++ptrsubopt)
					{
						r = new RecordVal(BifType::Record::DHCP::dhcp_sub_opt);
						Val* index = new Val(i + 1, TYPE_COUNT);
						r->Assign(0, new Val((*ptrsubopt)->code(), TYPE_COUNT));
						r->Assign(1, bytestring_to_val((*ptrsubopt)->value()));
						relay_agent_sub_opt->Assign(index, r);
						Unref(index);
						++i;
					}
					break;
				}
			}

			if ( host_name == 0 )
				host_name = new StringVal("");

		switch ( type )
			{
			case DHCPOFFER:
				if ( ! router_list )
					router_list = new TableVal(dhcp_router_list);

				BifEvent::generate_dhcp_offer(connection()->bro_analyzer(),
							      connection()->bro_analyzer()->Conn(),
							      dhcp_msg_val_->Ref(), new AddrVal(subnet_mask),
							      router_list, lease, new AddrVal(serv_addr), host_name);
				break;

			case DHCPACK:
				if ( ! router_list )
					router_list = new TableVal(dhcp_router_list);

				BifEvent::generate_dhcp_ack(connection()->bro_analyzer(),
							    connection()->bro_analyzer()->Conn(),
							    dhcp_msg_val_->Ref(), new AddrVal(subnet_mask),
							    router_list, lease, new AddrVal(serv_addr), host_name, reb_time, ren_time, relay_agent_sub_opt);
				break;

			case DHCPNAK:
				//Unref(router_list);
				BifEvent::generate_dhcp_nak(connection()->bro_analyzer(),
							    connection()->bro_analyzer()->Conn(),
							    dhcp_msg_val_->Ref(), host_name);
				break;

			default:
				//Unref(router_list);
				//Unref(host_name);
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

		std::string mac_str = fmt_mac(${msg.chaddr}.data(), ${msg.chaddr}.length());

		RecordVal* r = new RecordVal(dhcp_msg);
		r->Assign(0, new Val(${msg.op}, TYPE_COUNT));
		r->Assign(1, new Val(${msg.type}, TYPE_COUNT));
		r->Assign(2, new Val(${msg.xid}, TYPE_COUNT));
		r->Assign(3, new StringVal(mac_str));
		r->Assign(4, new AddrVal(${msg.ciaddr}));
		r->Assign(5, new AddrVal(${msg.yiaddr}));

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
				     ${msg.type} == DHCPNAK ||
				     ${msg.type} == DHCPLEASEUNASSIGNED ||
				     ${msg.type} == DHCPLEASEUNKNOWN ||
				     ${msg.type} == DHCPLEASEACTIVE )
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
