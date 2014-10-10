enum Trans_subcommands {
	NT_TRANSACT_QUERY_QUOTA = 0x0007,
	NT_TRANSACT_SET_QUOTA = 0x0008,
	NT_TRANSACT_CREATE2 = 0x0009,
};


refine connection SMB_Conn += {

	function proc_smb1_transaction_request(header: SMB_Header, val: SMB1_transaction_request): bool
		%{
		if ( smb1_transaction_request )
			BifEvent::generate_smb1_transaction_request(bro_analyzer(), bro_analyzer()->Conn(), BuildHeaderVal(header), \
														 smb_string2stringval(${val.name}), ${val.sub_cmd});
		return true;
		%}

	function proc_smb1_transaction_response(header: SMB_Header, val: SMB1_transaction_response): bool
		%{
		//printf("transaction_response\n");
		return true;
		%}

	function proc_smb1_transaction_setup(header: SMB_Header, val: SMB1_transaction_setup): bool
		%{
		if ( smb1_transaction_setup )
			BifEvent::generate_smb1_transaction_setup(bro_analyzer(), bro_analyzer()->Conn(), BuildHeaderVal(header), \
													  ${val.op_code}, ${val.file_id});
		return true;
		%}

};


type SMB1_transaction_data(header: SMB_Header, count: uint16, sub_cmd: uint16,
                          trans_type: TransactionType ) = case trans_type of {
#	SMB_MAILSLOT_BROWSE -> mailslot : SMB_MailSlot_message(header.unicode, count);
#	SMB_MAILSLOT_LANMAN -> lanman   : SMB_MailSlot_message(header.unicode, count);
#	SMB_RAP             -> rap      : SMB_Pipe_message(header.unicode, count);
	SMB_PIPE            -> pipe     : SMB_Pipe_message(header, count);
	SMB_UNKNOWN         -> unknown  : bytestring &restofdata;
#	default             -> data     : bytestring &restofdata;
};

type SMB1_transaction_setup(header: SMB_Header) = record {
	op_code	: uint16;
	file_id : uint16;
} &let {
	proc: bool = $context.connection.proc_smb1_transaction_setup(header, this);
}

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
	setup               : SMB1_transaction_setup(header);
	
	byte_count          : uint16;
	name                : SMB_string(header.unicode, offsetof(name));
	pad1                : padding to param_offset - SMB_Header_length;
	parameters          : bytestring &length = param_count;
	pad2                : padding to data_offset - SMB_Header_length;
	data                : SMB1_transaction_data(header, data_count, sub_cmd, determine_transaction_type(setup_count, name));
} &let {
	sub_cmd : uint16 = setup_count ? setup.op_code : 0;
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
	handle_response	    : case $context.connection.get_tree_is_pipe(header.tid) of {
		true -> pipe_data : SMB1_transaction_data(header, data_count, 0, SMB_PIPE);
		false -> unk_data : SMB1_transaction_data(header, data_count, 0, SMB_UNKNOWN);
	};
} &let {
	proc : bool = $context.connection.proc_smb1_transaction_response(header, this);
};
