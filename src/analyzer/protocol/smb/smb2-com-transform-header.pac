refine connection SMB_Conn += {

	function proc_smb2_transform_header(hdr: SMB2_transform_header) : bool
		%{
		if ( smb2_transform_header )
			{
			auto r = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SMB2::Transform_header);
			r->Assign(0, to_stringval(${hdr.signature}));
			r->Assign(1, to_stringval(${hdr.nonce}));
			r->Assign(2, ${hdr.orig_msg_size});
			r->Assign(3, ${hdr.flags});
			r->Assign(4, ${hdr.session_id});

			zeek::BifEvent::enqueue_smb2_transform_header(zeek_analyzer(),
			                                        zeek_analyzer()->Conn(),
			                                        std::move(r));
			}

		return true;
		%}

};

type SMB2_transform_header = record {
	signature         : bytestring &length = 16;
	nonce             : bytestring &length = 16;
	orig_msg_size     : uint32;
	reserved          : uint16;
	flags             : uint16;
	session_id	  : uint64;
} &let {
	proc: bool = $context.connection.proc_smb2_transform_header(this);
} &byteorder = littleendian;
