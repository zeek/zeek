%extern{
#include "analyzer/Manager.h"
%}

refine connection DCE_RPC_Conn += {
	%member{
		zeek::analyzer::Analyzer *gssapi;
		zeek::analyzer::Analyzer *ntlm;
	%}

	%init{
		ntlm = 0;
		gssapi = 0;
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

	function forward_auth(auth: DCE_RPC_Auth, is_orig: bool): bool
		%{
		switch ( ${auth.type} )
			{
			case 0x09:
				if ( ! gssapi )
					gssapi = zeek::analyzer_mgr->InstantiateAnalyzer("KRB", bro_analyzer()->Conn());
				if ( gssapi )
					gssapi->DeliverStream(${auth.blob}.length(), ${auth.blob}.begin(), is_orig);
				break;
			case 0x0a:
				if ( ! ntlm )
					ntlm = zeek::analyzer_mgr->InstantiateAnalyzer("NTLM", bro_analyzer()->Conn());
				if ( ntlm )
					ntlm->DeliverStream(${auth.blob}.length(), ${auth.blob}.begin(), is_orig);
				break;
			default:
				bro_analyzer()->Weird("unknown_dce_rpc_auth_type", zeek::util::fmt("%d", ${auth.type}));
				break;
			}

		return true;
		%}
};

refine typeattr DCE_RPC_Auth += &let {
	proc = $context.connection.forward_auth(this, true);
}
