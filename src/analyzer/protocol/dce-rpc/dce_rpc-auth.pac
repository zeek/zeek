%extern{
#include "zeek/analyzer/Manager.h"
%}

refine connection DCE_RPC_Conn += {
	%member{
		zeek::analyzer::Analyzer *gssapi;
		zeek::analyzer::Analyzer *ntlm;
		zeek::analyzer::Analyzer *krb;
	%}

	%init{
		ntlm = 0;
		gssapi = 0;
		krb = 0;
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
		if ( krb )
			{
			krb->Done();
			delete krb;
			}

	%}

	function forward_auth(auth: DCE_RPC_Auth, is_orig: bool): bool
		%{
		switch ( ${auth.type} )  // https://social.msdn.microsoft.com/Forums/en-US/44212c32-a4f6-4960-8799-0e00821650f4/msrpc-and-dcerpc-security?forum=os_windowsprotocols
			{
			case 0x09:
				if ( ! gssapi )
					gssapi = zeek::analyzer_mgr->InstantiateAnalyzer("GSSAPI", zeek_analyzer()->Conn());
				if ( gssapi )
					gssapi->DeliverStream(${auth.blob}.length(), ${auth.blob}.begin(), is_orig);
				break;

			case 0x10:
				if ( ! krb )
					krb = zeek::analyzer_mgr->InstantiateAnalyzer("KRB", zeek_analyzer()->Conn());
				if ( krb )
					krb->DeliverStream(${auth.blob}.length(), ${auth.blob}.begin(), is_orig);
				break;

			case 0x0a:
				if ( ! ntlm )
					ntlm = zeek::analyzer_mgr->InstantiateAnalyzer("NTLM", zeek_analyzer()->Conn());
				if ( ntlm )
					ntlm->DeliverStream(${auth.blob}.length(), ${auth.blob}.begin(), is_orig);
				break;

			case 0x0e:
				zeek_analyzer()->Weird("tls_dce_rpc_auth_type", zeek::util::fmt("%d", ${auth.type}));
				break;

			case 0x44:
				zeek_analyzer()->Weird("netlogon_dce_rpc_auth_type", zeek::util::fmt("%d", ${auth.type}));
				break;

			default:
				zeek_analyzer()->Weird("unknown_dce_rpc_auth_type", zeek::util::fmt("%d", ${auth.type}));
				break;
			}

		return true;
		%}
};

refine typeattr DCE_RPC_Auth += &let {
	proc = $context.connection.forward_auth(this, true);
}
