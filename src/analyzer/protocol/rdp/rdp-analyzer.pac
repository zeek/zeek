refine flow RDP_Flow += {
        function proc_rdp_debug(debug: Debug): bool
		%{
                  BifEvent::generate_rdp_debug(connection()->bro_analyzer(),
                                                      connection()->bro_analyzer()->Conn(),
                                                      bytestring_to_val(${debug.remainder}));

                  return true;
                %}


        function proc_rdp_ntlm_server_response(ntlm_server: NTLMServerResponse): bool
                %{
                  BifEvent::generate_rdp_ntlm_server_response(connection()->bro_analyzer(),
                                                      connection()->bro_analyzer()->Conn(),
                                                      bytestring_to_val(${ntlm_server.server_name}));

                  return true;
                %}

        function proc_rdp_ntlm_client_request(ntlm_client: NTLMClientRequest): bool
                %{
                  BifEvent::generate_rdp_ntlm_client_request(connection()->bro_analyzer(),
                                                      connection()->bro_analyzer()->Conn(),
                                                      bytestring_to_val(${ntlm_client.server_name}));

                  return true;
                %}

        function proc_rdp_native_client_request(client_request: ClientRequest): bool
                %{
                  BifEvent::generate_rdp_native_client_request(connection()->bro_analyzer(),
                                                      connection()->bro_analyzer()->Conn(),
                                                      bytestring_to_val(${client_request.cookie}));

                  return true;
                %}


        function proc_rdp_native_authentication(gcc_response: GCC_Server_CreateResponse): bool
                %{
                BifEvent::generate_rdp_native_authentication(connection()->bro_analyzer(),
                                                     connection()->bro_analyzer()->Conn(),
						     ${gcc_response.result});

		return true;
		%}


        function proc_rdp_native_client_info(ccore: ClientCore): bool
                %{
                BifEvent::generate_rdp_native_client_info(connection()->bro_analyzer(),
                                                    connection()->bro_analyzer()->Conn(),
                                                    ${ccore.keyboard_layout},
						    ${ccore.client_build},
						    bytestring_to_val(${ccore.client_name}),
                                                    bytestring_to_val(${ccore.dig_product_id}));

                return true;
                %}

        function proc_rdp_native_server_security(ssd: ServerSecurityData): bool
                %{
                BifEvent::generate_rdp_native_server_security(connection()->bro_analyzer(),
                                                    connection()->bro_analyzer()->Conn(),
                                                    ${ssd.encryption_method},
                                                    ${ssd.encryption_level},
						    bytestring_to_val(${ssd.server_random}),
						    bytestring_to_val(${ssd.server_certificate}));

                return true;
                %}
};

refine typeattr Debug += &let {
        proc: bool = $context.flow.proc_rdp_debug(this);
};

refine typeattr NTLMServerResponse += &let {
        proc: bool = $context.flow.proc_rdp_ntlm_server_response(this);
};

refine typeattr NTLMClientRequest += &let {
        proc: bool = $context.flow.proc_rdp_ntlm_client_request(this);
};

refine typeattr ClientRequest += &let {
        proc: bool = $context.flow.proc_rdp_native_client_request(this);
};

refine typeattr ClientCore += &let {
  proc: bool = $context.flow.proc_rdp_native_client_info(this);
};

refine typeattr GCC_Server_CreateResponse += &let {
        proc: bool = $context.flow.proc_rdp_native_authentication(this);
};

refine typeattr ServerSecurityData += &let {
        proc: bool = $context.flow.proc_rdp_native_server_security(this);
};
