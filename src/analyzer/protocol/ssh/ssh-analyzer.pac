refine flow SSH_Flow += {
	function proc_ssh_version(msg: SSH_Version): bool
		%{
		if ( ssh_client_version && ${msg.is_orig } )
			{
			BifEvent::generate_ssh_client_version(connection()->bro_analyzer(), 
							      connection()->bro_analyzer()->Conn(), 
							      bytestring_to_val(${msg.version}));
			}
		else if ( ssh_server_version )
			{
			BifEvent::generate_ssh_server_version(connection()->bro_analyzer(), 
							      connection()->bro_analyzer()->Conn(), 
							      bytestring_to_val(${msg.version}));
			}
		return true;
		%}

	function proc_ssh_kexinit(msg: SSH_KEXINIT): bool
		%{
		if ( ssh_server_capabilities )
			{
			BifEvent::generate_ssh_server_capabilities(connection()->bro_analyzer(), 
								   connection()->bro_analyzer()->Conn(),
						   		   bytestring_to_val(${msg.kex_algorithms.val}), 
								   bytestring_to_val(${msg.server_host_key_algorithms.val}),
						   		   bytestring_to_val(${msg.encryption_algorithms_client_to_server.val}), 
						   		   bytestring_to_val(${msg.encryption_algorithms_server_to_client.val}), 
						   		   bytestring_to_val(${msg.mac_algorithms_client_to_server.val}), 
						   		   bytestring_to_val(${msg.mac_algorithms_server_to_client.val}), 
						   		   bytestring_to_val(${msg.compression_algorithms_client_to_server.val}), 
						   		   bytestring_to_val(${msg.compression_algorithms_server_to_client.val}), 
						   		   bytestring_to_val(${msg.languages_client_to_server.val}), 
						   		   bytestring_to_val(${msg.languages_server_to_client.val}));
			}
		return true;
		%}

	function proc_ssh_server_host_key(key: bytestring): bool
		%{
		if ( ssh_server_host_key )
			{
			BifEvent::generate_ssh_server_host_key(connection()->bro_analyzer(), 
							       connection()->bro_analyzer()->Conn(), 
						  	       bytestring_to_val(${key}));
			}
		return true;
		%}

	function proc_ssh1_server_host_key(p: bytestring, e: bytestring): bool
		%{
		if ( ssh_server_host_key )
			{
			BifEvent::generate_ssh1_server_host_key(connection()->bro_analyzer(), 
							       	connection()->bro_analyzer()->Conn(), 
						  	       	bytestring_to_val(${p}),
						  	       	bytestring_to_val(${e}));
			}
		return true;
		%}

	function proc_newkeys(): bool
		%{
		connection()->bro_analyzer()->ProtocolConfirmation();
		return true;
		%}

};

refine typeattr SSH_Version += &let {
	proc: bool = $context.flow.proc_ssh_version(this);
};

refine typeattr SSH_KEXINIT += &let {
	proc: bool = $context.flow.proc_ssh_kexinit(this);
};

refine typeattr SSH_DH_GEX_REPLY += &let {
	proc: bool = $context.flow.proc_ssh_server_host_key(k_s.val);
};

refine typeattr SSH1_Message += &let {
	proc_newkeys: bool = $context.flow.proc_newkeys() &if(msg_type == SSH_CMSG_SESSION_KEY);
};

refine typeattr SSH2_Message += &let {
	proc_newkeys: bool = $context.flow.proc_newkeys() &if(msg_type == MSG_NEWKEYS);
};

refine typeattr SSH1_PUBLIC_KEY += &let {
       proc: bool = $context.flow.proc_ssh1_server_host_key(host_key_p.val, host_key_e.val);
};