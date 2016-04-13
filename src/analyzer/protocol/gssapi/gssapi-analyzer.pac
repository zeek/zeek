
refine connection GSSAPI_Conn += {
	%member{
		analyzer::Analyzer *ntlm;
	%}

	%init{
		ntlm = analyzer_mgr->InstantiateAnalyzer("NTLM", bro_analyzer->Conn());
	%}

	%cleanup{
		if ( ntlm )
			delete ntlm;
	%}

	function forward_ntlm(data: bytestring, is_orig: bool): bool
		%{
		if ( ntlm )
			ntlm->DeliverStream(${data}.length(), ${data}.begin(), is_orig);
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

refine typeattr GSSAPI_NEG_TOKEN_INIT_Arg_Data += &let {
	fwd: bool = $context.connection.forward_ntlm(mech_token, true) &if(index==2); 
};

refine typeattr GSSAPI_NEG_TOKEN_RESP_Arg += &let {
	proc: bool = $context.connection.proc_gssapi_neg_result(this) &if(seq_meta.index==0);
	fwd: bool = $context.connection.forward_ntlm(response_token, false) &if(seq_meta.index==2);
};

