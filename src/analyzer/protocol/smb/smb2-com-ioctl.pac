refine connection SMB_Conn += {
	
};

type SMB2_ioctl_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
	ctl_code          : uint32;
	file_id           : SMB2_guid;
	input_offset      : uint32;
	input_count       : uint32;
	max_input_resp    : uint32;
	output_offset     : uint32;
	output_count      : uint32;
	max_output_resp   : uint32;
	flags             : uint32;
	reserved2         : uint32;
	pad1              : bytestring &transient &length=((input_offset == 0) ? 0 : (offsetof(pad1) + header.head_length - input_offset));
	input_buffer      : bytestring &length=input_count;
	pad2              : bytestring &transient &length=((output_offset == 0 || output_offset == input_offset) ? 0 : (offsetof(pad2) + header.head_length - output_offset));
	output_buffer     : bytestring &length=output_count;
} &let {
	# We only handle FSCTL_PIPE_TRANSCEIVE messages right now.
	is_pipe: bool = (ctl_code == 0x0011C017);
	pipe_proc : bool = $context.connection.forward_dce_rpc(input_buffer, true) &if(is_pipe);
};

type SMB2_ioctl_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
	ctl_code          : uint32;
	file_id           : SMB2_guid;
	input_offset      : uint32;
	input_count       : uint32;
	output_offset     : uint32;
	output_count      : uint32;
	flags             : uint32;
	reserved2         : uint32;
	pad1              : bytestring &transient &length=((input_offset == 0) ? 0 : (offsetof(pad1) + header.head_length - input_offset));
	input_buffer      : bytestring &length=input_count;
	pad2              : bytestring &transient &length=((output_offset == 0 || output_offset == input_offset) ? 0 : (offsetof(pad2) + header.head_length - output_offset));
	output_buffer     : bytestring &length=output_count;
} &let {
	# We only handle FSCTL_PIPE_TRANSCEIVE messages right now.
	is_pipe: bool = (ctl_code == 0x0011C017);
	pipe_proc : bool = $context.connection.forward_dce_rpc(output_buffer, false) &if(is_pipe);
};