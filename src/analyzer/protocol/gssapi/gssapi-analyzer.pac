
refine connection GSSAPI_Conn += {
	%member{
		analyzer::Analyzer *ntlm;
		analyzer::Analyzer *krb5;
	%}

	%init{
		ntlm=0;
		krb5=0;
	%}

	%cleanup{
		if ( ntlm )
			{
			ntlm->Done();
			delete ntlm;
			ntlm=0;
			}

		if ( krb5 )
			{
			krb5->Done();
			delete krb5;
			krb5=0;
			}
	%}

	function forward_blob(val: GSSAPI_NEG_TOKEN_MECH_TOKEN, is_orig: bool): bool
		%{
		if ( ${val.mech_token}.length() >= 7 &&
		     memcmp("NTLMSSP", ${val.mech_token}.begin(), 7) == 0 )
			{
			// ntlmssp
			if ( ! ntlm )
				ntlm = analyzer_mgr->InstantiateAnalyzer("NTLM", bro_analyzer()->Conn());

			if ( ntlm )
				ntlm->DeliverStream(${val.mech_token}.length(), ${val.mech_token}.begin(), is_orig);
			}
		else if ( ${val.mech_token}.length() == 9 &&
		          (memcmp("\x2a\x86\x48\x86\xf7\x12\x01\x02\x02", ${val.mech_token}.begin(), ${val.mech_token}.length()) == 0 ||
		           memcmp("\x2a\x86\x48\x82\xf7\x12\x01\x02\x02", ${val.mech_token}.begin(), ${val.mech_token}.length()) == 0 ) )
			{
			// krb5 && ms-krb5
			if ( ! krb5 )
				krb5 = analyzer_mgr->InstantiateAnalyzer("KRB", bro_analyzer()->Conn());

			// 0x0100 is a special marker
			if ( krb5 && memcmp("\x01\x00", ${val.mech_token}.begin(), 2) == 0 )
				{
				krb5->DeliverPacket(${val.mech_token}.length()-2, ${val.mech_token}.begin()+2, is_orig, 0, 0, 0);
				}
			}

		return true;
		%}

	function proc_gssapi_neg_result(val: GSSAPI_NEG_TOKEN_RESP_Arg): bool
		%{
		if ( gssapi_neg_result )
			{
			BifEvent::generate_gssapi_neg_result(bro_analyzer(),
			                                     bro_analyzer()->Conn(),
			                                     binary_to_int64(${val.neg_state.encoding.content}));
			}

		return true;
		%}
}

refine typeattr GSSAPI_NEG_TOKEN_MECH_TOKEN += &let {
	fwd: bool = $context.connection.forward_blob(this, is_orig);
};

refine typeattr GSSAPI_NEG_TOKEN_RESP_Arg += &let {
	proc: bool = $context.connection.proc_gssapi_neg_result(this) &if(seq_meta.index==0);
};

