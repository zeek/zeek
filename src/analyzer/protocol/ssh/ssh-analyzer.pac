%extern{
#include <cstdlib>
#include <vector>
#include <string>
%}

%header{
VectorVal* name_list_to_vector(const bytestring nl);
%}

%code{
// Copied from IRC_Analyzer::SplitWords
VectorVal* name_list_to_vector(const bytestring nl)
	{
	VectorVal* vv = new VectorVal(internal_type("string_vec")->AsVectorType());

	string name_list = std_str(nl);
	if ( name_list.size() < 1 )
		return vv;

	unsigned int start = 0;
	unsigned int split_pos = 0;

	while ( name_list[start] == ',' )
		{
		++start;
		++split_pos;
		}

	string word;
	while ( (split_pos = name_list.find(',', start)) < name_list.size() )
		{
		word = name_list.substr(start, split_pos - start);
		if ( word.size() > 0 && word[0] != ',' )
			vv->Assign(vv->Size(), new StringVal(word));

		start = split_pos + 1;
		}

	// Add line end if needed.
	if ( start < name_list.size() )
		{
		word = name_list.substr(start, name_list.size() - start);
		vv->Assign(vv->Size(), new StringVal(word));
		}

	return vv;
	}
%}

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
		if ( ssh_capabilities )
			{
			RecordVal* result = new RecordVal(BifType::Record::SSH::Capabilities);
			result->Assign(0, name_list_to_vector(${msg.kex_algorithms.val}));
			result->Assign(1, name_list_to_vector(${msg.server_host_key_algorithms.val}));
			result->Assign(2, name_list_to_vector(${msg.encryption_algorithms_client_to_server.val}));
			result->Assign(3, name_list_to_vector(${msg.encryption_algorithms_server_to_client.val}));
			result->Assign(4, name_list_to_vector(${msg.mac_algorithms_client_to_server.val}));
			result->Assign(5, name_list_to_vector(${msg.mac_algorithms_server_to_client.val}));
			result->Assign(6, name_list_to_vector(${msg.compression_algorithms_client_to_server.val}));
			result->Assign(7, name_list_to_vector(${msg.compression_algorithms_server_to_client.val}));
			if ( ${msg.languages_client_to_server.len} )
				result->Assign(8, name_list_to_vector(${msg.languages_client_to_server.val}));
			if ( ${msg.languages_server_to_client.len} )
				result->Assign(9, name_list_to_vector(${msg.languages_server_to_client.val}));
			result->Assign(10, new Val(${msg.is_orig}, TYPE_BOOL));

			BifEvent::generate_ssh_capabilities(connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(), bytestring_to_val(${msg.cookie}),
				result);
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
		if ( ssh1_server_host_key )
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

refine typeattr SSH1_Message += &let {
	proc_newkeys: bool = $context.flow.proc_newkeys() &if(msg_type == SSH_CMSG_SESSION_KEY);
};

refine typeattr SSH2_Message += &let {
	proc_newkeys: bool = $context.flow.proc_newkeys() &if(msg_type == MSG_NEWKEYS);
};

refine typeattr SSH_DH_GEX_REPLY += &let {
	proc: bool = $context.flow.proc_ssh_server_host_key(k_s.val);
};

refine typeattr SSH_ECC_REPLY += &let {
	proc: bool = $context.flow.proc_ssh_server_host_key(k_s.val);
};

refine typeattr SSH1_PUBLIC_KEY += &let {
	proc: bool = $context.flow.proc_ssh1_server_host_key(host_key_p.val, host_key_e.val);
};