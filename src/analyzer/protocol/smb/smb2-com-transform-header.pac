refine connection SMB_Conn += {

	function BuildSMB2TransformHeaderVal(hdr: SMB2_transform_header): BroVal
		%{
		RecordVal* r = new RecordVal(BifType::Record::SMB2::Transform_header);

		r->Assign(0, bytestring_to_val(${hdr.signature}));
		r->Assign(1, bytestring_to_val(${hdr.nonce}));
		r->Assign(2, val_mgr->Count(${hdr.orig_msg_size}));
		r->Assign(3, val_mgr->Count(${hdr.flags}));
		r->Assign(4, val_mgr->Count(${hdr.session_id}));

		return r;
		%}

	function proc_smb2_transform_header(hdr: SMB2_transform_header) : bool
		%{
		if ( smb2_transform_header )
			BifEvent::enqueue_smb2_transform_header(bro_analyzer(),
			                                        bro_analyzer()->Conn(),
			                                        {AdoptRef{}, BuildSMB2TransformHeaderVal(hdr)});

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
