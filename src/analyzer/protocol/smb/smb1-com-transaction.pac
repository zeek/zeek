enum Trans_subcommands {
	NT_TRANSACT_QUERY_QUOTA = 0x0007,
	NT_TRANSACT_SET_QUOTA = 0x0008,
	NT_TRANSACT_CREATE2 = 0x0009,
};

refine connection SMB_Conn += {

	%member{
		map<uint16, bool> is_file_a_pipe;
	%}

	function get_is_file_a_pipe(id: uint16): bool
		%{
		if ( is_file_a_pipe.count(id) > 0 )
			{
			bool is_pipe = is_file_a_pipe.at(id);
			is_file_a_pipe.erase(id);

			return is_pipe;
			}
		else
			return false;
		%}

	function set_is_file_a_pipe(id: uint16, is_it: bool): bool
		%{
		is_file_a_pipe[id] = is_it;
		return true;
		%}

	function proc_smb1_transaction_request(header: SMB_Header, val: SMB1_transaction_request): bool
		%{
		if ( ! smb1_transaction_request )
			return false;

		StringVal* parameters = new StringVal(${val.parameters}.length(),
		                                      (const char*)${val.parameters}.data());
		StringVal* payload_str = nullptr;
		SMB1_transaction_data* payload = nullptr;

		if ( ${val.data_count} > 0 )
			{
			payload = ${val.data};
			}

		if ( payload )
			{
			switch ( payload->trans_type() ) {
			case SMB_PIPE:
				payload_str = new StringVal(${val.data_count}, (const char*)${val.data.pipe_data}.data());
				break;
			case SMB_UNKNOWN:
				payload_str = new StringVal(${val.data_count}, (const char*)${val.data.unknown}.data());
				break;
			default:
				payload_str = new StringVal(${val.data_count}, (const char*)${val.data.data}.data());
				break;
			}
			}

		if ( ! payload_str )
			{
			payload_str = new StringVal("");
			}

		BifEvent::generate_smb1_transaction_request(bro_analyzer(),
		                                            bro_analyzer()->Conn(),
		                                            BuildHeaderVal(header),
		                                            smb_string2stringval(${val.name}),
		                                            ${val.sub_cmd},
		                                            parameters,
		                                            payload_str);

		return true;
		%}

	function proc_smb1_transaction_response(header: SMB_Header, val: SMB1_transaction_response): bool
		%{
		if ( ! smb1_transaction_response )
			return false;

		StringVal* parameters = new StringVal(${val.parameters}.length(),
		                                      (const char*)${val.parameters}.data());
		StringVal* payload_str = nullptr;
		SMB1_transaction_data* payload = nullptr;

		if ( ${val.data_count} > 0 )
			{
			payload = ${val.data[0]};
			}

		if ( payload )
			{
			switch ( payload->trans_type() ) {
			case SMB_PIPE:
				payload_str = new StringVal(${val.data_count}, (const char*)${val.data[0].pipe_data}.data());
				break;
			case SMB_UNKNOWN:
				payload_str = new StringVal(${val.data_count}, (const char*)${val.data[0].unknown}.data());
				break;
			default:
				payload_str = new StringVal(${val.data_count}, (const char*)${val.data[0].data}.data());
				break;
			}
			}

		if ( ! payload_str )
			{
			payload_str = new StringVal("");
			}

		BifEvent::generate_smb1_transaction_response(bro_analyzer(),
		                                             bro_analyzer()->Conn(),
		                                             BuildHeaderVal(header),
		                                             parameters,
		                                             payload_str);
		return true;
		%}
};


type SMB1_transaction_data(header: SMB_Header, is_orig: bool, count: uint16, sub_cmd: uint16,
                           trans_type: int, is_pipe: bool) = case trans_type of {
#	SMB_MAILSLOT_BROWSE -> mailslot  : SMB_MailSlot_message(header.unicode, count);
#	SMB_MAILSLOT_LANMAN -> lanman    : SMB_MailSlot_message(header.unicode, count);
#	SMB_RAP             -> rap       : SMB_Pipe_message(header.unicode, count);
	SMB_PIPE            -> pipe_data : bytestring &restofdata;
	SMB_UNKNOWN         -> unknown   : bytestring &restofdata;
	default             -> data      : bytestring &restofdata;
} &let {
	pipe_proc : bool = $context.connection.forward_dce_rpc(pipe_data, 0, is_orig) &if(trans_type == SMB_PIPE);
};

type SMB1_transaction_request(header: SMB_Header) = record {
	word_count          : uint8;
	total_param_count   : uint16;
	total_data_count    : uint16;
	max_param_count     : uint16;
	max_data_count      : uint16;
	max_setup_count     : uint8;
	reserved1           : uint8;
	flags               : uint16;
	timeout             : uint32;
	reserved2           : uint16;
	param_count         : uint16;
	param_offset        : uint16;
	data_count          : uint16;
	data_offset         : uint16;
	setup_count         : uint8;
	reserved3           : uint8;
	# word_count 16 is a different dialect that behaves a bit differently.
	setup               : uint16[setup_count];

	byte_count          : uint16;
	name                : SMB_string(header.unicode, offsetof(name));
	pad1                : padding to param_offset - SMB_Header_length;
	parameters          : bytestring &length = param_count;
	pad2                : padding to data_offset - SMB_Header_length;
	data                : SMB1_transaction_data(header, true, data_count, sub_cmd, transtype, is_pipe);
} &let {
	sub_cmd : uint16 = (sizeof(setup) && word_count != 16) > 0 ? setup[0] : 0;
	transtype : int = determine_transaction_type(header, name);
	is_pipe : bool = (transtype == SMB_PIPE || (transtype == SMB_UNKNOWN && $context.connection.get_tree_is_pipe(header.tid)));

	proc_set_pipe : bool = $context.connection.set_is_file_a_pipe(header.mid, is_pipe);
	proc : bool = $context.connection.proc_smb1_transaction_request(header, this);
};

type SMB1_transaction_response(header: SMB_Header) = record {
	word_count          : uint8;
	total_param_count   : uint16;
	total_data_count    : uint16;
	reserved            : uint16;
	param_count         : uint16;
	param_offset        : uint16;
	param_displacement  : uint16;
	data_count          : uint16;
	data_offset         : uint16;
	data_displacement   : uint16;
	setup_count         : uint8;
	reserved2           : uint8;
	setup               : uint16[setup_count];

	byte_count          : uint16;
	pad0                : padding to param_offset - SMB_Header_length;
	parameters          : bytestring &length = param_count;
	pad1                : padding to data_offset - SMB_Header_length;
	data                : SMB1_transaction_data(header, false, data_count, 0, is_pipe ? SMB_PIPE : SMB_UNKNOWN, is_pipe)[data_count>0 ? 1 : 0];
} &let {
	proc : bool = $context.connection.proc_smb1_transaction_response(header, this);
	is_pipe: bool = $context.connection.get_is_file_a_pipe(header.mid);
};
