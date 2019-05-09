// See the file "COPYING" in the main distribution directory for copyright.

#include "FDDI.h"
#include "NetVar.h"

using namespace zeek::llanalyzer::FDDI;

FDDIAnalyzer::FDDIAnalyzer()
	: zeek::llanalyzer::Analyzer("FDDI")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> FDDIAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;
	auto hdr_size = 13 + 8; // FDDI header + LLC

	if ( pdata + hdr_size >= packet->GetEndOfData() )
		{
		packet->Weird("FDDI_analyzer_failed");
		return { AnalyzerResult::Failed, 0 };
		}

	// We just skip the header and hope for default analysis
	pdata += hdr_size;
	return { AnalyzerResult::Continue, -1 };
	}
