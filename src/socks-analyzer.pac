
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
	function socks_request(cmd: uint8, dstaddr: uint32, dstname: uint8[], p: uint16, user: uint8[]): bool
		%{
		BifEvent::generate_socks_request(bro_analyzer(),
		                                 bro_analyzer()->Conn(),
		                                 cmd,
		                                 new AddrVal(htonl(dstaddr)),
		                                 array_to_string(dstname),
		                                 new PortVal(p | TCP_PORT_MASK),
		                                 array_to_string(user));
	
		static_cast<SOCKS_Analyzer*>(bro_analyzer())->EndpointDone(true);
	
		return true;
		%}

	function socks_reply(granted: bool, dst: uint32, p: uint16): bool
		%{
		BifEvent::generate_socks_reply(bro_analyzer(),
		                               bro_analyzer()->Conn(), 
		                               granted,
		                               new AddrVal(htonl(dst)),
		                               new PortVal(p | TCP_PORT_MASK));
		
		bro_analyzer()->ProtocolConfirmation();
		static_cast<SOCKS_Analyzer*>(bro_analyzer())->EndpointDone(false);
		return true;
		%}
};

refine typeattr SOCKS_Request += &let {
	proc: bool = $context.connection.socks_request(command, addr, empty, port, user);
};

refine typeattr SOCKS_Reply += &let {
	proc: bool = $context.connection.socks_reply((status == 0x5a), addr, port);
};
