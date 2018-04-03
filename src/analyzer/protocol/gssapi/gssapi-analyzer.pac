
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
		if ( ${val.has_ntlm} &&
		     ${val.ntlm}.length() >= 7 &&
		     memcmp("NTLMSSP", ${val.ntlm}.begin(), 7) == 0 )
			{
			// ntlmssp
			if ( ! ntlm )
				ntlm = analyzer_mgr->InstantiateAnalyzer("NTLM", bro_analyzer()->Conn());

			if ( ntlm )
				ntlm->DeliverStream(${val.ntlm}.length(),
				                    ${val.ntlm}.begin(), is_orig);
			}

		else if ( ${val.has_krb} )
			{
			if ( ! krb5 )
				krb5 = analyzer_mgr->InstantiateAnalyzer("KRB", bro_analyzer()->Conn());

			if ( krb5 ) // accepting all KRB types (REQ, REP, etc)
				{
				krb5->DeliverPacket(${val.krb.blob}.length(),
				                    ${val.krb.blob}.begin(),
				                    is_orig, 0, 0, 0);
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

