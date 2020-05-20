// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "Telnet.h"
#include "NVT.h"

#include "events.bif.h"

using namespace analyzer::login;

Telnet_Analyzer::Telnet_Analyzer(Connection* conn)
: Login_Analyzer("TELNET", conn)
	{
	NVT_Analyzer* nvt_orig = new NVT_Analyzer(conn, true);
	NVT_Analyzer* nvt_resp = new NVT_Analyzer(conn, false);

	nvt_resp->SetPeer(nvt_orig);
	nvt_orig->SetPeer(nvt_resp);

	AddSupportAnalyzer(nvt_orig);
	AddSupportAnalyzer(nvt_resp);
	}

