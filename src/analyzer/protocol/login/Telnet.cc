// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/login/Telnet.h"

#include "zeek/zeek-config.h"

#include "zeek/analyzer/protocol/login/NVT.h"
#include "zeek/analyzer/protocol/login/events.bif.h"

namespace zeek::analyzer::login
	{

Telnet_Analyzer::Telnet_Analyzer(Connection* conn) : Login_Analyzer("TELNET", conn)
	{
	NVT_Analyzer* nvt_orig = new NVT_Analyzer(conn, true);
	NVT_Analyzer* nvt_resp = new NVT_Analyzer(conn, false);

	nvt_resp->SetPeer(nvt_orig);
	nvt_orig->SetPeer(nvt_resp);

	AddSupportAnalyzer(nvt_orig);
	AddSupportAnalyzer(nvt_resp);
	}

	} // namespace zeek::analyzer::login
