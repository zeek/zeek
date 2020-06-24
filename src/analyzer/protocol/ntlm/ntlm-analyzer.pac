%header{
	ValPtr filetime2brotime(uint64_t ts);
	RecordValPtr build_version_record(NTLM_Version* val);
	RecordValPtr build_negotiate_flag_record(NTLM_Negotiate_Flags* val);
%}

%code{
	// This is replicated from the SMB analyzer. :(
	ValPtr filetime2brotime(uint64_t ts)
		{
		double secs = (ts / 10000000.0);

		// Bro can't support times back to the 1600's
		// so we subtract a lot of seconds.
		auto bro_ts = zeek::make_intrusive<TimeVal>(secs - 11644473600.0);

		return bro_ts;
		}

	RecordValPtr build_version_record(NTLM_Version* val)
		{
		auto result = zeek::make_intrusive<RecordVal>(zeek::BifType::Record::NTLM::Version);
		result->Assign(0, val_mgr->Count(${val.major_version}));
		result->Assign(1, val_mgr->Count(${val.minor_version}));
		result->Assign(2, val_mgr->Count(${val.build_number}));
		result->Assign(3, val_mgr->Count(${val.ntlm_revision}));

		return result;
		}

	RecordValPtr build_negotiate_flag_record(NTLM_Negotiate_Flags* val)
		{
		auto flags = zeek::make_intrusive<RecordVal>(zeek::BifType::Record::NTLM::NegotiateFlags);
		flags->Assign(0, val_mgr->Bool(${val.negotiate_56}));
		flags->Assign(1, val_mgr->Bool(${val.negotiate_key_exch}));
		flags->Assign(2, val_mgr->Bool(${val.negotiate_128}));
		flags->Assign(3, val_mgr->Bool(${val.negotiate_version}));
		flags->Assign(4, val_mgr->Bool(${val.negotiate_target_info}));
		flags->Assign(5, val_mgr->Bool(${val.request_non_nt_session_key}));
		flags->Assign(6, val_mgr->Bool(${val.negotiate_identify}));
		flags->Assign(7, val_mgr->Bool(${val.negotiate_extended_sessionsecurity}));
		flags->Assign(8, val_mgr->Bool(${val.target_type_server}));
		flags->Assign(9, val_mgr->Bool(${val.target_type_domain}));
		flags->Assign(10, val_mgr->Bool(${val.negotiate_always_sign}));
		flags->Assign(11, val_mgr->Bool(${val.negotiate_oem_workstation_supplied}));
		flags->Assign(12, val_mgr->Bool(${val.negotiate_oem_domain_supplied}));
		flags->Assign(13, val_mgr->Bool(${val.negotiate_anonymous_connection}));
		flags->Assign(14, val_mgr->Bool(${val.negotiate_ntlm}));
		flags->Assign(15, val_mgr->Bool(${val.negotiate_lm_key}));
		flags->Assign(16, val_mgr->Bool(${val.negotiate_datagram}));
		flags->Assign(17, val_mgr->Bool(${val.negotiate_seal}));
		flags->Assign(18, val_mgr->Bool(${val.negotiate_sign}));
		flags->Assign(19, val_mgr->Bool(${val.request_target}));
		flags->Assign(20, val_mgr->Bool(${val.negotiate_oem}));
		flags->Assign(21, val_mgr->Bool(${val.negotiate_unicode}));

		return flags;
		}
%}

refine connection NTLM_Conn += {

	function build_av_record(val: NTLM_AV_Pair_Sequence, len: uint16): BroVal
		%{
		RecordVal* result = new RecordVal(zeek::BifType::Record::NTLM::AVs);
		for ( uint i = 0; ; i++ )
			{
			if ( i >= ${val.pairs}->size() )
				{
				if ( len != 0 )
					// According to spec, the TargetInfo MUST be a sequence of
					// AV_PAIRs and terminated by the null AV_PAIR when the
					// TargetInfoLen is non-zero, so this is in violation.
					bro_analyzer()->ProtocolViolation("NTLM AV Pair loop underflow");

				return result;
				}

			switch ( ${val.pairs[i].id} )
				{
				case 0:
					return result;
				case 1:
					result->Assign(0, utf16_to_utf8_val(bro_analyzer()->Conn(), ${val.pairs[i].nb_computer_name.data}));
					break;
				case 2:
					result->Assign(1, utf16_to_utf8_val(bro_analyzer()->Conn(), ${val.pairs[i].nb_domain_name.data}));
					break;
				case 3:
					result->Assign(2, utf16_to_utf8_val(bro_analyzer()->Conn(), ${val.pairs[i].dns_computer_name.data}));
					break;
				case 4:
					result->Assign(3, utf16_to_utf8_val(bro_analyzer()->Conn(), ${val.pairs[i].dns_domain_name.data}));
					break;
				case 5:
					result->Assign(4, utf16_to_utf8_val(bro_analyzer()->Conn(), ${val.pairs[i].dns_tree_name.data}));
					break;
				case 6:
					result->Assign(5, val_mgr->Bool(${val.pairs[i].constrained_auth}));
					break;
				case 7:
					result->Assign(6, filetime2brotime(${val.pairs[i].timestamp}));
					break;
				case 8:
					result->Assign(7, val_mgr->Count(${val.pairs[i].single_host.machine_id}));
					break;
				case 9:
					result->Assign(8, utf16_to_utf8_val(bro_analyzer()->Conn(), ${val.pairs[i].target_name.data}));
					break;
				}
			}
		return result;
		%}

	function proc_ntlm_negotiate(val: NTLM_Negotiate): bool
		%{
		if ( ! ntlm_negotiate )
			return true;

		auto result = zeek::make_intrusive<RecordVal>(zeek::BifType::Record::NTLM::Negotiate);
		result->Assign(0, build_negotiate_flag_record(${val.flags}));

		if ( ${val}->has_domain_name() )
		        result->Assign(1, utf16_to_utf8_val(bro_analyzer()->Conn(), ${val.domain_name.string.data}));

		if ( ${val}->has_workstation() )
		        result->Assign(2, utf16_to_utf8_val(bro_analyzer()->Conn(), ${val.workstation.string.data}));

		if ( ${val}->has_version() )
		        result->Assign(3, build_version_record(${val.version}));

		zeek::BifEvent::enqueue_ntlm_negotiate(bro_analyzer(),
		                                 bro_analyzer()->Conn(),
		                                 std::move(result));

		return true;
		%}

	function proc_ntlm_challenge(val: NTLM_Challenge): bool
		%{
		if ( ! ntlm_challenge )
			return true;

		auto result = zeek::make_intrusive<RecordVal>(zeek::BifType::Record::NTLM::Challenge);
		result->Assign(0, build_negotiate_flag_record(${val.flags}));

		if ( ${val}->has_target_name() )
			result->Assign(1, utf16_to_utf8_val(bro_analyzer()->Conn(), ${val.target_name.string.data}));

		if ( ${val}->has_version() )
			result->Assign(2, build_version_record(${val.version}));

		if ( ${val}->has_target_info() )
			result->Assign(3, {zeek::AdoptRef{}, build_av_record(${val.target_info},  ${val.target_info_fields.length})});

		zeek::BifEvent::enqueue_ntlm_challenge(bro_analyzer(),
		                                 bro_analyzer()->Conn(),
		                                 std::move(result));

		return true;
		%}

	function proc_ntlm_authenticate(val: NTLM_Authenticate): bool
		%{
		if ( ! ntlm_authenticate )
			return true;

		auto result = zeek::make_intrusive<RecordVal>(zeek::BifType::Record::NTLM::Authenticate);
		result->Assign(0, build_negotiate_flag_record(${val.flags}));

		if ( ${val}->has_domain_name() > 0 )
			result->Assign(1, utf16_to_utf8_val(bro_analyzer()->Conn(), ${val.domain_name.string.data}));

		if ( ${val}->has_user_name() > 0 )
			result->Assign(2, utf16_to_utf8_val(bro_analyzer()->Conn(), ${val.user_name.string.data}));

		if ( ${val}->has_workstation() > 0 )
			result->Assign(3, utf16_to_utf8_val(bro_analyzer()->Conn(), ${val.workstation.string.data}));

		if ( ${val}->has_encrypted_session_key() > 0 )
			result->Assign(4, to_stringval(${val.encrypted_session_key.string.data}));

		if ( ${val}->has_version() )
			result->Assign(5, build_version_record(${val.version}));

		zeek::BifEvent::enqueue_ntlm_authenticate(bro_analyzer(),
		                                    bro_analyzer()->Conn(),
		                                    std::move(result));
		return true;
		%}
}

refine typeattr NTLM_Negotiate += &let {
	proc = $context.connection.proc_ntlm_negotiate(this);
};

refine typeattr NTLM_Challenge += &let {
	proc : bool = $context.connection.proc_ntlm_challenge(this);
};

refine typeattr NTLM_Authenticate += &let {
	proc : bool = $context.connection.proc_ntlm_authenticate(this);
};
