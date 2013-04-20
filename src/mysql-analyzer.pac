refine connection MySQL_Conn += {
       function command_request(): bool 
       %{
       BifEvent::generate_mysql_command_request(bro_analyzer(), 
						bro_analyzer()->Conn()
					       );
       return true;
       %}

       function command_response(): bool 
       %{
       BifEvent::generate_mysql_command_response(bro_analyzer(), 
						bro_analyzer()->Conn()
					       );
       return true;
       %}

       function initial_handshake(): bool 
       %{
       BifEvent::generate_mysql_initial_handshake(bro_analyzer(), 
						bro_analyzer()->Conn()
					       );
       return true;
       %}

       function handshake_response(): bool 
       %{
       BifEvent::generate_mysql_handshake_response(bro_analyzer(), 
						bro_analyzer()->Conn()
					       );
       return true;
       %}
};

refine typeattr Command_Request_Packet += &let {
       proc: bool = $context.connection.command_request();
};

refine typeattr Command_Response_Packet += &let {
       proc: bool = $context.connection.command_response();
};

refine typeattr Initial_Handshake_Packet += &let {
       proc: bool = $context.connection.initial_handshake();
};

refine typeattr Handshake_Response_Packet += &let {
       proc: bool = $context.connection.handshake_response();
};
