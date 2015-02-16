refine flow RDP_Flow += {
        function proc_rdp_client_request(client_request: Client_Request): bool
                %{
                connection()->bro_analyzer()->ProtocolConfirmation();

                BifEvent::generate_rdp_client_request(connection()->bro_analyzer(),
                                                      connection()->bro_analyzer()->Conn(),
                                                      bytestring_to_val(${client_request.cookie_value}));

                return true;
                %}

        function proc_rdp_result(gcc_response: GCC_Server_Create_Response): bool
                %{
                connection()->bro_analyzer()->ProtocolConfirmation();
                BifEvent::generate_rdp_result(connection()->bro_analyzer(),
                                              connection()->bro_analyzer()->Conn(),
					      ${gcc_response.result});

		return true;
		%}


        function proc_rdp_client_data(ccore: Client_Core_Data): bool
                %{
                connection()->bro_analyzer()->ProtocolConfirmation();
                BifEvent::generate_rdp_client_data(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   ${ccore.keyboard_layout},
						   ${ccore.client_build},
						   bytestring_to_val(${ccore.client_name}),
                                                   bytestring_to_val(${ccore.dig_product_id}));

                return true;
                %}

        function proc_rdp_server_security(ssd: Server_Security_Data): bool
                %{
                connection()->bro_analyzer()->ProtocolConfirmation();
                BifEvent::generate_rdp_server_security(connection()->bro_analyzer(),
                                                       connection()->bro_analyzer()->Conn(),
                                                       ${ssd.encryption_method},
                                                       ${ssd.encryption_level});

                return true;
                %}
};

refine typeattr Client_Request += &let {
        proc: bool = $context.flow.proc_rdp_client_request(this);
};

refine typeattr Client_Core_Data += &let {
  proc: bool = $context.flow.proc_rdp_client_data(this);
};

refine typeattr GCC_Server_Create_Response += &let {
        proc: bool = $context.flow.proc_rdp_result(this);
};

refine typeattr Server_Security_Data += &let {
        proc: bool = $context.flow.proc_rdp_server_security(this);
};
