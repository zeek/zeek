refine flow RDP_Flow += {
        function proc_rdp_client_request(client_request: ClientRequest): bool
                %{
                  BifEvent::generate_rdp_client_request(connection()->bro_analyzer(),
                                                        connection()->bro_analyzer()->Conn(),
                                                        bytestring_to_val(${client_request.cookie}));

                  return true;
                %}


        function proc_rdp_result(gcc_response: GCC_Server_CreateResponse): bool
                %{
                BifEvent::generate_rdp_result(connection()->bro_analyzer(),
                                              connection()->bro_analyzer()->Conn(),
					      ${gcc_response.result});

		return true;
		%}


        function proc_rdp_client_data(ccore: ClientCore): bool
                %{
                BifEvent::generate_rdp_client_data(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   ${ccore.keyboard_layout},
						   ${ccore.client_build},
						   bytestring_to_val(${ccore.client_name}),
                                                   bytestring_to_val(${ccore.dig_product_id}));

                return true;
                %}

        function proc_rdp_server_security(ssd: ServerSecurityData): bool
                %{
                BifEvent::generate_rdp_server_security(connection()->bro_analyzer(),
                                                       connection()->bro_analyzer()->Conn(),
                                                       ${ssd.encryption_method},
                                                       ${ssd.encryption_level});

                return true;
                %}
};

refine typeattr ClientRequest += &let {
        proc: bool = $context.flow.proc_rdp_client_request(this);
};

refine typeattr ClientCore += &let {
  proc: bool = $context.flow.proc_rdp_client_data(this);
};

refine typeattr GCC_Server_CreateResponse += &let {
        proc: bool = $context.flow.proc_rdp_result(this);
};

refine typeattr ServerSecurityData += &let {
        proc: bool = $context.flow.proc_rdp_server_security(this);
};
