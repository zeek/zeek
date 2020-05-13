
refine flow DHCP_Flow += {
	%member{
		IntrusivePtr<RecordVal> options;
		IntrusivePtr<VectorVal> all_options;
	%}

	%init{
		options = nullptr;
		all_options = nullptr;
	%}

	%cleanup{
		options = nullptr;
		all_options = nullptr;
	%}

	function init_options(): bool
		%{
		if ( ! options )
			{
			options = make_intrusive<RecordVal>(BifType::Record::DHCP::Options);
			all_options = make_intrusive<VectorVal>(zeek::id::index_vec);
			options->Assign(0, all_options);
			}

		return true;
		%}

	function create_options(code: uint8): bool
		%{
		init_options();

		if ( code != 255 )
			all_options->Assign(all_options->Size(), val_mgr->Count(code));

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
			std::string mac_str = fmt_mac(${msg.chaddr}.data(), ${msg.chaddr}.length());
			double secs = static_cast<double>(${msg.secs});

			auto dhcp_msg_val = make_intrusive<RecordVal>(BifType::Record::DHCP::Msg);
			dhcp_msg_val->Assign(0, val_mgr->Count(${msg.op}));
			dhcp_msg_val->Assign(1, val_mgr->Count(${msg.type}));
			dhcp_msg_val->Assign(2, val_mgr->Count(${msg.xid}));
			dhcp_msg_val->Assign(3, make_intrusive<Val>(secs, TYPE_INTERVAL));
			dhcp_msg_val->Assign(4, val_mgr->Count(${msg.flags}));
			dhcp_msg_val->Assign(5, make_intrusive<AddrVal>(htonl(${msg.ciaddr})));
			dhcp_msg_val->Assign(6, make_intrusive<AddrVal>(htonl(${msg.yiaddr})));
			dhcp_msg_val->Assign(7, make_intrusive<AddrVal>(htonl(${msg.siaddr})));
			dhcp_msg_val->Assign(8, make_intrusive<AddrVal>(htonl(${msg.giaddr})));
			dhcp_msg_val->Assign(9, make_intrusive<StringVal>(mac_str));

			int last_non_null = 0;

			for ( int i = 0; i < ${msg.sname}.length(); ++i )
				{
				if ( *(${msg.sname}.begin() + i) != 0 )
					last_non_null = i;
				}

			if ( last_non_null > 0 )
				dhcp_msg_val->Assign(10, make_intrusive<StringVal>(last_non_null + 1,
				                                                   reinterpret_cast<const char*>(${msg.sname}.begin())));

			last_non_null = 0;

			for ( int i = 0; i < ${msg.file_n}.length(); ++i )
				{
				if ( *(${msg.file_n}.begin() + i) != 0 )
					last_non_null = i;
				}

			if ( last_non_null > 0 )
				dhcp_msg_val->Assign(11, make_intrusive<StringVal>(last_non_null + 1,
				                                                   reinterpret_cast<const char*>(${msg.file_n}.begin())));

			init_options();

			BifEvent::enqueue_dhcp_message(connection()->bro_analyzer(),
			                               connection()->bro_analyzer()->Conn(),
			                               ${msg.is_orig},
			                               std::move(dhcp_msg_val),
			                               std::move(options));

			options = nullptr;
			all_options = nullptr;
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

