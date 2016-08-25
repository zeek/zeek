
refine connection SMB_Conn += {
	%member{
		analyzer::Analyzer *gssapi;
	%}

	%init{
		gssapi = 0;
	%}

	%cleanup{
		if ( gssapi )
			{
			gssapi->Done();
			delete gssapi;
			}
	%}

	function forward_gssapi(data: bytestring, is_orig: bool): bool
		%{
		if ( ! gssapi )
			gssapi = analyzer_mgr->InstantiateAnalyzer("GSSAPI", bro_analyzer()->Conn());

		if ( gssapi )
			gssapi->DeliverStream(${data}.length(), ${data}.begin(), is_orig);

		return true;
		%}
};
