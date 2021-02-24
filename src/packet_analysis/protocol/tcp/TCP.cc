// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/tcp/TCP.h"
#include "zeek/RunState.h"
#include "zeek/session/Manager.h"

using namespace zeek::packet_analysis::TCP;

TCPAnalyzer::TCPAnalyzer()
	: zeek::packet_analysis::Analyzer("TCP_PKT")
	{
	}

TCPAnalyzer::~TCPAnalyzer()
	{
	}

bool TCPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	session_mgr->ProcessTransportLayer(run_state::processing_start_time, packet, len);
	return true;
	}
