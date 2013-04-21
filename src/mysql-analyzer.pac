refine connection MySQL_Conn += {

       %member{
		int state_;
		StringVal* username_;
	%}

	%init{
		state_ = CONNECTION_PHASE;
		username_ = new StringVal("No username available.");
	%}

	function get_state(): int
	%{ return state_; %}

       function command_request(command: int, arg: const_bytestring): bool 
       %{
       BifEvent::generate_mysql_command_request(bro_analyzer(), 
						bro_analyzer()->Conn(),
						command, bytestring_to_val(arg)
					       );
       return true;
       %}

       function command_request_no_arg(command: int): bool 
       %{
       BifEvent::generate_mysql_command_request(bro_analyzer(), 
						bro_analyzer()->Conn(),
						command, new StringVal("")
					       );
       return true;
       %}

       function command_response(response: int): bool 
       %{
       BifEvent::generate_mysql_command_response(bro_analyzer(), 
						bro_analyzer()->Conn(),
						response
					       );
       return true;
       %}

       function initial_handshake(version: const_bytestring): bool 
       %{
       BifEvent::generate_mysql_server_version(bro_analyzer(), 
				 	       bro_analyzer()->Conn(),
					       bytestring_to_val(version)
					       );
       return true;
       %}

       function ok_packet(): bool
       %{
       if (state_ == CONNECTION_PHASE) {
       	  state_ = COMMAND_PHASE;
	  BifEvent::generate_mysql_login(bro_analyzer(),
						    bro_analyzer()->Conn(),
						    username_, 1);
	}
	else {
	  BifEvent::generate_mysql_command_response(bro_analyzer(),
	                                            bro_analyzer()->Conn(),
						    0);
	}
	return true;
       %}

       function err_packet(): bool
       %{
       if (state_ == CONNECTION_PHASE) {
	  BifEvent::generate_mysql_login(bro_analyzer(),
				         bro_analyzer()->Conn(),
					 username_, 0);
	}
	else {
	  BifEvent::generate_mysql_command_response(bro_analyzer(),
	                                            bro_analyzer()->Conn(),
						    255);
	}
	return true;
       %}

       function handshake_response(username: const_bytestring): bool 
       %{
       username_ = bytestring_to_val(username);
       return true;
       %}
};

refine typeattr Command_Request_Packet += &let {
       init_db_arg_proc: bool = $context.connection.command_request(command, init_db_arg) &if(command == COM_INIT_DB);
       query_arg_proc: bool = $context.connection.command_request(command, query_arg) &if(command == COM_QUERY);
       create_db_arg_proc: bool = $context.connection.command_request(command, create_db_arg) &if(command == COM_CREATE_DB);
       drop_db_arg_proc: bool = $context.connection.command_request(command, drop_db_arg) &if(command == COM_DROP_DB);
       quit_arg_proc: bool = $context.connection.command_request_no_arg(command) &if(command == COM_QUIT);
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

