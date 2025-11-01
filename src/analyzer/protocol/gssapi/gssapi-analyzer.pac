
refine connection GSSAPI_Conn += {
	%member{
		zeek::analyzer::Analyzer *ntlm;
		zeek::analyzer::Analyzer *krb5;
	%}

	%init{
		ntlm = nullptr;
		krb5 = nullptr;
	%}

	%cleanup{
		if ( ntlm )
			{
			ntlm->Done();
			delete ntlm;
			ntlm = nullptr;
			}

		if ( krb5 )
			{
			krb5->Done();
			delete krb5;
			krb5 = nullptr;
			}
	%}

	function forward_blob(val: GSSAPI_NEG_TOKEN_MECH_TOKEN, is_orig: bool): bool
		%{
		if ( ${val.has_ntlm} &&
		     ${val.ntlm}.length() >= 7 &&
		     memcmp("NTLMSSP", ${val.ntlm}.begin(), 7) == 0 )
			{
			// ntlmssp
			if ( ! ntlm )
				ntlm = zeek::analyzer_mgr->InstantiateAnalyzer("NTLM", zeek_analyzer()->Conn());

			if ( ntlm )
				ntlm->DeliverStream(${val.ntlm}.length(),
				                    ${val.ntlm}.begin(), is_orig);
			}

		else if ( ${val.has_krb_with_oid} )
			{
			if ( ! krb5 )
				krb5 = zeek::analyzer_mgr->InstantiateAnalyzer("KRB", zeek_analyzer()->Conn());

			if ( krb5 ) // accepting all KRB types (REQ, REP, etc)
				{
				krb5->DeliverPacket(${val.krb_with_oid.blob}.length(),
				                    ${val.krb_with_oid.blob}.begin(),
				                    is_orig, 0, nullptr, 0);
				}
			}

		else if ( ${val.has_krb_blob} )
			{
			if ( ! krb5 )
				krb5 = zeek::analyzer_mgr->InstantiateAnalyzer("KRB", zeek_analyzer()->Conn());

			if ( krb5 ) // accepting all KRB types (REQ, REP, etc)
				{
				krb5->DeliverPacket(${val.krb_blob}.length(),
				                    ${val.krb_blob}.begin(),
				                    is_orig, 0, nullptr, 0);
				}
			}

		return true;
		%}

	function proc_gssapi_neg_result(val: GSSAPI_NEG_TOKEN_RESP_Arg): bool
		%{
		if ( gssapi_neg_result )
			{
			zeek::BifEvent::enqueue_gssapi_neg_result(zeek_analyzer(),
			                                    zeek_analyzer()->Conn(),
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
