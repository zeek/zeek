// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/unknown_ip/UnknownIPSessionAdapter.h"

#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/conn-size/ConnSize.h"

using namespace zeek::packet_analysis::UnknownIP;
using namespace zeek::packet_analysis::IP;

void UnknownIPSessionAdapter::AddExtraAnalyzers(Connection* conn) {
    static zeek::Tag analyzer_connsize = analyzer_mgr->GetComponentTag("CONNSIZE");

    if ( analyzer_mgr->IsEnabled(analyzer_connsize) )
        // Add ConnSize analyzer. Needs to see packets, not stream.
        AddChildAnalyzer(new analyzer::conn_size::ConnSize_Analyzer(conn));
}
