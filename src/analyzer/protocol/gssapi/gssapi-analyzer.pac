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

	function proc_gssapi_neg_token(val: GSSAPI_NEG_TOKEN): bool
		%{
		if ( ${val.is_init} )
			return true;
		
		for ( uint i = 0; i < ${val.resp.args}->size(); ++i )
			{
			switch ( ${val.resp.args[i].seq_meta.index} )
				{
				case 0:
					if ( ${val.resp.args[i].args.neg_state} == 0 )
						{
						BifEvent::generate_gssapi_accepted(bro_analyzer(), 
						                                   bro_analyzer()->Conn());
						}
					break;
				
				default:
					break;
				}
			}
		return true;
		%}
}

refine typeattr GSSAPI_NEG_TOKEN += &let {
	proc : bool = $context.connection.proc_gssapi_neg_token(this);
};
