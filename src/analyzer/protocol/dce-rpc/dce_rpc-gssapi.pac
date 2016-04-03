refine connection DCE_RPC_Conn += {
	%member{
		analyzer::Analyzer *gssapi;
		analyzer::Analyzer *ntlm;
	%}

	%init{
		gssapi = analyzer_mgr->InstantiateAnalyzer("GSSAPI", bro_analyzer->Conn());
		ntlm = analyzer_mgr->InstantiateAnalyzer("NTLM", bro_analyzer->Conn());
	%}

	%cleanup{
		if ( gssapi )
			delete gssapi;
		if ( ntlm )
			delete ntlm;
	%}

	function forward_auth(auth: DCE_RPC_Auth, is_orig: bool): bool
		%{
		switch ( ${auth.type} )
			{
			case 0x0a:
				if ( ntlm )
					ntlm->DeliverStream(${auth.blob}.length(), ${auth.blob}.begin(), is_orig);
				break;
			//case 0xXX:
			//	if ( gssapi )
			//		gssapi->DeliverStream(${data}.length(), ${data}.begin(), is_orig);
			//	break;
			default:
				bro_analyzer()->Weird(fmt("unknown_dce_rpc_auth_type_%d",${auth.type}));
				break;
			}

		return true;
		%}
};

refine typeattr DCE_RPC_Auth += &let {
	proc = $context.connection.forward_auth(this, true);
}
