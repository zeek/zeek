
refine flow DHCP_Flow += {
	%member{
		RecordVal *dhcp_msg_val;
		RecordVal *options;
	%}

	%init{
		dhcp_msg_val = 0;
		options = 0;
	%}

	%cleanup{
		Unref(dhcp_msg_val);
		dhcp_msg_val = 0;

		Unref(options);
		options = 0;
	%}

	function parse_request(options: Option[], type: uint8): bool
		%{
//		// Requested IP address to the server.
//		::uint32 req_addr = 0, serv_addr = 0;
//		StringVal* host_name = new StringVal("");
//
//		TableVal* params_list = 0;
//		RecordVal* client_id = new RecordVal(BifType::Record::DHCP::ClientID);
//		client_id->Assign(0,0);
//		client_id->Assign(1,new StringVal(""));
//
//		switch ( type )
//			{
//			case DHCPDISCOVER:
//				BifEvent::generate_dhcp_discover(connection()->bro_analyzer(),
//				                                 connection()->bro_analyzer()->Conn(),
//				                                 dhcp_msg_val->Ref(), new AddrVal(req_addr),
//				                                 host_name, client_id, params_list);
//				break;
//
//			case DHCPREQUEST:
//				BifEvent::generate_dhcp_request(connection()->bro_analyzer(),
//				                                connection()->bro_analyzer()->Conn(),
//				                                dhcp_msg_val->Ref(), new AddrVal(req_addr),
//				                                new AddrVal(serv_addr), host_name, client_id, params_list);
//				break;
//
//			case DHCPDECLINE:
//				BifEvent::generate_dhcp_decline(connection()->bro_analyzer(),
//				                                connection()->bro_analyzer()->Conn(),
//				                                dhcp_msg_val->Ref(), host_name);
//				break;
//
//			case DHCPRELEASE:
//				BifEvent::generate_dhcp_release(connection()->bro_analyzer(),
//				                                connection()->bro_analyzer()->Conn(),
//				                                dhcp_msg_val->Ref(), host_name);
//				break;
//
//			case DHCPINFORM:
//				BifEvent::generate_dhcp_inform(connection()->bro_analyzer(),
//				                               connection()->bro_analyzer()->Conn(),
//				                               dhcp_msg_val->Ref(), host_name, params_list);
//				break;
//
//			default:
//				Unref(host_name);
//				break;
//			}

		return true;
		%}

	function parse_reply(options: Option[], type: uint8): bool
		%{
//		// RFC 1533 allows a list of router addresses.
//		TableVal* router_list = 0;
//
//		::uint32 subnet_mask = 0, serv_addr = 0;
//
//		uint32 lease = 0;
//		StringVal* host_name = 0;
//
//		uint32 reb_time = 0;
//		uint32 ren_time = 0;
//		StringVal* agent_cir = 0;
//		StringVal* agent_rem = 0;
//		StringVal* agent_sub_opt = 0;
//		TableVal* relay_agent_sub_opt = new TableVal(BifType::Table::DHCP::SubOptList);
//
//		if ( host_name == nullptr )
//			host_name = new StringVal("");
//
//		switch ( type )
//			{
//			case DHCPOFFER:
//				if ( ! router_list )
//					router_list = new TableVal(BifType::Table::DHCP::RouterList);
//
//				BifEvent::generate_dhcp_offer(connection()->bro_analyzer(),
//				                              connection()->bro_analyzer()->Conn(),
//				                              dhcp_msg_val->Ref(), new AddrVal(subnet_mask),
//				                              router_list, lease, new AddrVal(serv_addr), host_name);
//				break;
//
//			case DHCPACK:
//				if ( ! router_list )
//					router_list = new TableVal(BifType::Table::DHCP::RouterList);
//
//				BifEvent::generate_dhcp_ack(connection()->bro_analyzer(),
//				                            connection()->bro_analyzer()->Conn(),
//				                            dhcp_msg_val->Ref(), new AddrVal(subnet_mask),
//				                            router_list, lease, new AddrVal(serv_addr), host_name, reb_time, ren_time, relay_agent_sub_opt);
//				break;
//
//			case DHCPNAK:
//				//Unref(router_list);
//				BifEvent::generate_dhcp_nak(connection()->bro_analyzer(),
//				                            connection()->bro_analyzer()->Conn(),
//				                            dhcp_msg_val->Ref(), host_name);
//				break;
//
//			default:
//				//Unref(router_list);
//				//Unref(host_name);
//				break;
//			}
//
		return true;
		%}

	function create_options(): bool
		%{
		if ( options == nullptr )
			options = new RecordVal(BifType::Record::DHCP::Options);

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

		Unref(dhcp_msg_val);

		std::string mac_str = fmt_mac(${msg.chaddr}.data(), ${msg.chaddr}.length());

		dhcp_msg_val = new RecordVal(BifType::Record::DHCP::Msg);
		dhcp_msg_val->Assign(0, new Val(${msg.op}, TYPE_COUNT));
		dhcp_msg_val->Assign(1, new Val(${msg.type}, TYPE_COUNT));
		dhcp_msg_val->Assign(2, new Val(${msg.xid}, TYPE_COUNT));
		dhcp_msg_val->Assign(3, new StringVal(mac_str));
		dhcp_msg_val->Assign(4, new AddrVal(${msg.ciaddr}));
		dhcp_msg_val->Assign(5, new AddrVal(${msg.yiaddr}));

		if ( dhcp_message )
			BifEvent::generate_dhcp_message(connection()->bro_analyzer(),
			                                connection()->bro_analyzer()->Conn(),
			                                ${msg.is_orig},
			                                dhcp_msg_val->Ref(),
			                                options->Ref());

		Unref(dhcp_msg_val);
		dhcp_msg_val = 0;
		Unref(options);
		options = 0;

		//switch ( ${msg.op} )
		//	{
		//	case BOOTREQUEST:	// presumably from client to server
		//		if ( ${msg.type} == DHCPDISCOVER ||
		//		     ${msg.type} == DHCPREQUEST ||
		//		     ${msg.type} == DHCPDECLINE ||
		//		     ${msg.type} == DHCPRELEASE ||
		//		     ${msg.type} == DHCPINFORM )
		//			{
		//			parse_request(${msg.options}, ${msg.type});
		//			}
		//		else
		//			{
		//			connection()->bro_analyzer()->ProtocolViolation(fmt("unknown DHCP message type option for BOOTREQUEST (%d)",
		//			                                                ${msg.type}));
		//			}
		//		break;
		//
		//	case BOOTREPLY:		// presumably from server to client
		//		if ( ${msg.type} == DHCPOFFER ||
		//		     ${msg.type} == DHCPACK ||
		//		     ${msg.type} == DHCPNAK ||
		//		     ${msg.type} == DHCPLEASEUNASSIGNED ||
		//		     ${msg.type} == DHCPLEASEUNKNOWN ||
		//		     ${msg.type} == DHCPLEASEACTIVE )
		//			{
		//			parse_reply(${msg.options}, ${msg.type});
		//			}
		//		else
		//			{
		//			connection()->bro_analyzer()->ProtocolViolation(fmt("unknown DHCP message type option for BOOTREPLY (%d)",
		//			                                                ${msg.type}));
		//			}
		//
		//		break;
		//
		//	default:
		//		// Removing this because I've seen some packets with weird values
		//		// but they still parse fine.
		//		//connection()->bro_analyzer()->ProtocolViolation(fmt("unknown DHCP message op code (%d). Known codes: 1=BOOTREQUEST, 2=BOOTREPLY",
		//		//                                                ${msg.op}));
		//		break;
		//	}

		// A single message reaching this point is enough to confirm the protocol
		// because it's not uncommon to see a single DHCP message
		// on a "connection".
		// The binpac analyzer would have thrown an error before this point
		// if there was a problem too (and subsequently called ProtocolViolation).
		connection()->bro_analyzer()->ProtocolConfirmation();

		return true;
		%}
};

refine typeattr DHCP_Message += &let {
	proc_dhcp_message = $context.flow.process_dhcp_message(this);
};

refine typeattr Option += &let {
	proc_create_options = $context.flow.create_options();
};

