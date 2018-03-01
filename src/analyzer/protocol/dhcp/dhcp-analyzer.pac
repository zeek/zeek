
refine flow DHCP_Flow += {
	%member{
		RecordVal *dhcp_msg_val;
		RecordVal *options;
		VectorVal* all_options;
	%}

	%init{
		dhcp_msg_val = 0;
		options = 0;
		all_options = 0;
	%}

	%cleanup{
		Unref(dhcp_msg_val);
		dhcp_msg_val = 0;

		Unref(options);
		options = 0;

		Unref(all_options);
		all_options = 0;
	%}

	function create_options(code: uint8): bool
		%{
		if ( options == nullptr )
			{
			options = new RecordVal(BifType::Record::DHCP::Options);
			all_options = new VectorVal(index_vec);
			options->Assign(0, all_options->Ref());
			}

		if ( code != 255 )
			all_options->Assign(all_options->Size(), new Val(code, TYPE_COUNT));

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

		if ( dhcp_message )
			{
			// Since this is a new message, let's make sure an old 
			// one is gone.
			Unref(dhcp_msg_val);

			std::string mac_str = fmt_mac(${msg.chaddr}.data(), ${msg.chaddr}.length());
			double secs = static_cast<double>(${msg.secs});

			dhcp_msg_val = new RecordVal(BifType::Record::DHCP::Msg);
			dhcp_msg_val->Assign(0, new Val(${msg.op}, TYPE_COUNT));
			dhcp_msg_val->Assign(1, new Val(${msg.type}, TYPE_COUNT));
			dhcp_msg_val->Assign(2, new Val(${msg.xid}, TYPE_COUNT));
			dhcp_msg_val->Assign(3, new Val(secs, TYPE_INTERVAL));
			dhcp_msg_val->Assign(4, new Val(${msg.flags}, TYPE_COUNT));
			dhcp_msg_val->Assign(5, new AddrVal(htonl(${msg.ciaddr})));
			dhcp_msg_val->Assign(6, new AddrVal(htonl(${msg.yiaddr})));
			dhcp_msg_val->Assign(7, new AddrVal(htonl(${msg.siaddr})));
			dhcp_msg_val->Assign(8, new AddrVal(htonl(${msg.giaddr})));
			dhcp_msg_val->Assign(9, new StringVal(mac_str));

			int last_non_null = 0;
			for ( int i=0; i < ${msg.sname}.length(); i++ )
				{
				if ( *(${msg.sname}.begin()+i) != 0 )
					last_non_null = i;
				}
			if ( last_non_null > 0 )
				dhcp_msg_val->Assign(10, new StringVal(last_non_null+1,
				                                       reinterpret_cast<const char*>(${msg.sname}.begin())));

			last_non_null = 0;
			for ( int i=0; i < ${msg.file_n}.length(); i++ )
				{
				if ( *(${msg.file_n}.begin()+i) != 0 )
					last_non_null = i;
				}
			if ( last_non_null > 0 )
				dhcp_msg_val->Assign(11, new StringVal(last_non_null+1,
				                                       reinterpret_cast<const char*>(${msg.file_n}.begin())));

			BifEvent::generate_dhcp_message(connection()->bro_analyzer(),
			                                connection()->bro_analyzer()->Conn(),
			                                ${msg.is_orig},
			                                dhcp_msg_val->Ref(),
			                                options->Ref());

			Unref(dhcp_msg_val);
			dhcp_msg_val = 0;
			Unref(options);
			options = 0;
			Unref(all_options);
			all_options = 0;
			}

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
	proc_create_options = $context.flow.create_options(code);
};

