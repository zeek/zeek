refine connection MySQL_Conn += {

	%member{
		StringVal* username_;
	%}

	%init{
		username_ = new StringVal("No username available.");
	%}

	function blah(): bool 
		%{
		printf("yo!\n");
		return true;
		%}

	function command_request(req: Command_Request_Packet): bool 
		%{
		StringVal *arg;
		if ( ${req.arg}.length() > 0 )
			arg = bytestring_to_val(${req.arg});
		else
			arg = new StringVal("");

		BifEvent::generate_mysql_command_request(bro_analyzer(), 
		                                         bro_analyzer()->Conn(),
		                                         ${req.command}, 
		                                         arg);
		return true;
		%}

	function command_response(response: int): bool 
		%{
		BifEvent::generate_mysql_command_response(bro_analyzer(), 
		                                          bro_analyzer()->Conn(),
		                                          response);
		return true;
		%}

	function initial_handshake(version: const_bytestring): bool 
		%{
		BifEvent::generate_mysql_server_version(bro_analyzer(), 
		                                        bro_analyzer()->Conn(),
		                                        bytestring_to_val(version));
		return true;
		%}

	function ok_packet(): bool
		%{
		//if (state_ == CONNECTION_PHASE) 
		//	{
			//state_ = COMMAND_PHASE;
			BifEvent::generate_mysql_login(bro_analyzer(),
			                               bro_analyzer()->Conn(),
			                               username_,
			                               1);
		//	}
		//else 
		//	{
		//	BifEvent::generate_mysql_command_response(bro_analyzer(),
		//	                                          bro_analyzer()->Conn(),
		//	                                          0);
		//	}
		return true;
		%}

	function err_packet(): bool
		%{
		//if (state_ == CONNECTION_PHASE)
		//	{
		//	BifEvent::generate_mysql_login(bro_analyzer(),
		//	                               bro_analyzer()->Conn(),
		//	                               username_,
		//	                               0);
		//	}
		//else
		//	{
		//	BifEvent::generate_mysql_command_response(bro_analyzer(),
		//	                                          bro_analyzer()->Conn(),
		//	                                          255);
		//	}
		return true;
		%}

	function handshake_response(username: const_bytestring): bool 
		%{
		username_ = bytestring_to_val(username);
		return true;
		%}
};

refine typeattr Command_Response += &let {
	blah: bool = $context.connection.blah();
}

refine typeattr Command_Request_Packet += &let {
	proc: bool = $context.connection.command_request(this);
};

refine typeattr Handshake_v10 += &let {
	proc: bool = $context.connection.initial_handshake(server_version);
};

refine typeattr Handshake_Response_Packet += &let {
	proc: bool = $context.connection.handshake_response(username);
};

refine typeattr OK_Packet += &let {
	proc: bool = $context.connection.ok_packet();
};

refine typeattr ERR_Packet += &let {
	proc: bool = $context.connection.err_packet();
};

