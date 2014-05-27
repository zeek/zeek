
%header{
StringVal* array_to_string(vector<uint8> *a);
%}

%code{
StringVal* array_to_string(vector<uint8> *a)
	{
	int len = a->size();
	char tmp[len];
	char *s = tmp;
	for ( vector<uint8>::iterator i = a->begin(); i != a->end(); *s++ = *i++ );

	while ( len > 0 && tmp[len-1] == '\0' )
		--len;

	return new StringVal(len, tmp);
	}
%}

refine connection SOCKS_Conn += {

	function socks4_request(request: SOCKS4_Request): bool
		%{
		RecordVal* sa = new RecordVal(socks_address);
		sa->Assign(0, new AddrVal(htonl(${request.addr})));
		if ( ${request.v4a} )
			sa->Assign(1, array_to_string(${request.name}));

		BifEvent::generate_socks_request(bro_analyzer(),
		                                 bro_analyzer()->Conn(),
		                                 4,
		                                 ${request.command},
		                                 sa,
		                                 new PortVal(${request.port} | TCP_PORT_MASK),
		                                 array_to_string(${request.user}));

		static_cast<analyzer::socks::SOCKS_Analyzer*>(bro_analyzer())->EndpointDone(true);

		return true;
		%}

	function socks4_reply(reply: SOCKS4_Reply): bool
		%{
		RecordVal* sa = new RecordVal(socks_address);
		sa->Assign(0, new AddrVal(htonl(${reply.addr})));

		BifEvent::generate_socks_reply(bro_analyzer(),
		                               bro_analyzer()->Conn(),
		                               4,
		                               ${reply.status},
		                               sa,
		                               new PortVal(${reply.port} | TCP_PORT_MASK));

		bro_analyzer()->ProtocolConfirmation();
		static_cast<analyzer::socks::SOCKS_Analyzer*>(bro_analyzer())->EndpointDone(false);
		return true;
		%}

	function socks5_request(request: SOCKS5_Request): bool
		%{
		if ( ${request.reserved} != 0 )
			{
			bro_analyzer()->ProtocolViolation(fmt("invalid value in reserved field: %d", ${request.reserved}));
			bro_analyzer()->SetSkip(true);
			return false;
			}

		if ( (${request.command} == 0) || (${request.command} > 3) )
			{
			bro_analyzer()->ProtocolViolation(fmt("undefined value in command field: %d", ${request.command}));
			bro_analyzer()->SetSkip(true);
			return false;
			}

		RecordVal* sa = new RecordVal(socks_address);

		// This is dumb and there must be a better way (checking for presence of a field)...
		switch ( ${request.remote_name.addr_type} )
			{
			case 1:
				sa->Assign(0, new AddrVal(htonl(${request.remote_name.ipv4})));
				break;

			case 3:
				sa->Assign(1, new StringVal(${request.remote_name.domain_name.name}.length(),
				                         (const char*) ${request.remote_name.domain_name.name}.data()));
				break;

			case 4:
				sa->Assign(0, new AddrVal(IPAddr(IPv6, (const uint32_t*) ${request.remote_name.ipv6}, IPAddr::Network)));
				break;

			default:
				bro_analyzer()->ProtocolViolation(fmt("invalid SOCKSv5 addr type: %d", ${request.remote_name.addr_type}));
				Unref(sa);
				return false;
			}

		BifEvent::generate_socks_request(bro_analyzer(),
		                                 bro_analyzer()->Conn(),
		                                 5,
		                                 ${request.command},
		                                 sa,
		                                 new PortVal(${request.port} | TCP_PORT_MASK),
		                                 new StringVal(""));

		static_cast<analyzer::socks::SOCKS_Analyzer*>(bro_analyzer())->EndpointDone(true);

		return true;
		%}

	function socks5_reply(reply: SOCKS5_Reply): bool
		%{
		RecordVal* sa = new RecordVal(socks_address);
		
		// This is dumb and there must be a better way (checking for presence of a field)...
		switch ( ${reply.bound.addr_type} )
			{
			case 1:
				sa->Assign(0, new AddrVal(htonl(${reply.bound.ipv4})));
				break;

			case 3:
				sa->Assign(1, new StringVal(${reply.bound.domain_name.name}.length(),
				                         (const char*) ${reply.bound.domain_name.name}.data()));
				break;

			case 4:
				sa->Assign(0, new AddrVal(IPAddr(IPv6, (const uint32_t*) ${reply.bound.ipv6}, IPAddr::Network)));
				break;

			default:
				bro_analyzer()->ProtocolViolation(fmt("invalid SOCKSv5 addr type: %d", ${reply.bound.addr_type}));
				Unref(sa);
				return false;
			}

		BifEvent::generate_socks_reply(bro_analyzer(),
		                               bro_analyzer()->Conn(),
		                               5,
		                               ${reply.reply},
		                               sa,
		                               new PortVal(${reply.port} | TCP_PORT_MASK));

		bro_analyzer()->ProtocolConfirmation();
		static_cast<analyzer::socks::SOCKS_Analyzer*>(bro_analyzer())->EndpointDone(false);
		return true;
		%}

	function version_error(version: uint8): bool
		%{
		bro_analyzer()->ProtocolViolation(fmt("unsupported/unknown SOCKS version %d", version));
		return true;
		%}


};

refine typeattr SOCKS_Version_Error += &let {
	proc: bool = $context.connection.version_error(version);
};

refine typeattr SOCKS4_Request += &let {
	proc: bool = $context.connection.socks4_request(this);
};

refine typeattr SOCKS4_Reply += &let {
	proc: bool = $context.connection.socks4_reply(this);
};

refine typeattr SOCKS5_Request += &let {
	proc: bool = $context.connection.socks5_request(this);
};

refine typeattr SOCKS5_Reply += &let {
	proc: bool = $context.connection.socks5_reply(this);
};
