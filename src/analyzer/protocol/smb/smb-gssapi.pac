
refine connection SMB_Conn += {
	%member{
		analyzer::Analyzer *gssapi;
		analyzer::Analyzer *ntlm;
	%}

	%init{
		gssapi = 0;
		ntlm = 0;
	%}

	%cleanup{
		if ( gssapi )
			{
			gssapi->Done();
			delete gssapi;
			}

		if ( ntlm )
			{
			ntlm->Done();
			delete ntlm;
			}
	%}

	function forward_gssapi(data: bytestring, is_orig: bool): bool
		%{
		if ( ! gssapi )
			gssapi = analyzer_mgr->InstantiateAnalyzer("GSSAPI", bro_analyzer()->Conn());

		if ( ! ntlm )
			ntlm = analyzer_mgr->InstantiateAnalyzer("NTLM", bro_analyzer()->Conn());

		// SMB allows raw NTLM instead of GSSAPI in certain messages.
		// We check if this is the case and run the NTLM analyzer directly.
		if ( ${data}.length() >= 8 )
			{
			if ( strncmp((const char*)${data}.begin(), "NTLMSSP",7) == 0 )
				{
				if ( ntlm )
					ntlm->DeliverStream(${data}.length(), ${data}.begin(), is_orig);
				}
			else
				{
				if ( gssapi )
					gssapi->DeliverStream(${data}.length(), ${data}.begin(), is_orig);
				}
			}
		return true;
		%}
};
