refine connection SMB_Conn += {
	%member{
		std::map<uint64,uint64> smb2_ioctl_fids;
	%}

	function get_ioctl_fid(message_id: uint64): uint64
		%{
		auto it = smb2_ioctl_fids.find(message_id);

		if ( it == smb2_ioctl_fids.end() )
			return 0;

		uint64 fid = it->second;
		smb2_ioctl_fids.erase(it);
		return fid;
		%}

	function proc_smb2_ioctl_request(val: SMB2_ioctl_request) : bool
		%{
		if ( zeek::BifConst::SMB::max_pending_messages > 0 &&
		     smb2_ioctl_fids.size() >= zeek::BifConst::SMB::max_pending_messages )
			{
			if ( smb2_discarded_messages_state )
				zeek::BifEvent::enqueue_smb2_discarded_messages_state(zeek_analyzer(), zeek_analyzer()->Conn(),
				                                                     zeek::make_intrusive<zeek::StringVal>("ioctl"));


			smb2_ioctl_fids.clear();
			}

		smb2_ioctl_fids[${val.header.message_id}] = ${val.file_id.persistent} + ${val.file_id._volatile};
		return true;
		%}

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
	fid: uint64 = file_id.persistent + file_id._volatile;
	pipe_proc : bool = $context.connection.forward_dce_rpc(input_buffer, fid, true) &if(is_pipe);
	proc : bool = $context.connection.proc_smb2_ioctl_request(this);
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
	is_pipe   : bool = (ctl_code == 0x0011C017);
	fid       : uint64 = $context.connection.get_ioctl_fid(header.message_id);
	pipe_proc : bool = $context.connection.forward_dce_rpc(output_buffer, fid, false) &if(is_pipe);
};
