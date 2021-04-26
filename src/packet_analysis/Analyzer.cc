// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/Analyzer.h"

#include "zeek/Dict.h"
#include "zeek/DebugLogger.h"
#include "zeek/RunState.h"
#include "zeek/session/SessionManager.h"
#include "zeek/util.h"

namespace zeek::packet_analysis {

Analyzer::Analyzer(std::string name)
	{
	Tag t = packet_mgr->GetComponentTag(name);

	if ( ! t )
		reporter->InternalError("unknown packet_analysis name %s", name.c_str());

	Init(t);
	}

Analyzer::Analyzer(const Tag& tag)
	{
	Init(tag);
	}

void Analyzer::Init(const Tag& _tag)
	{
	tag = _tag;
	}

void Analyzer::Initialize()
	{
	default_analyzer = LoadAnalyzer("default_analyzer");
	}

zeek::packet_analysis::AnalyzerPtr Analyzer::LoadAnalyzer(const std::string &name)
	{
	auto& analyzer = zeek::id::find(GetModuleName() + name);
	if ( ! analyzer )
		return nullptr;

	auto& analyzer_val = analyzer->GetVal();
	if ( ! analyzer_val )
		return nullptr;

	return packet_mgr->GetAnalyzer(analyzer_val->AsEnumVal());
	}

const Tag Analyzer::GetAnalyzerTag() const
	{
	assert(tag);
	return tag;
	}

const char* Analyzer::GetAnalyzerName() const
	{
	assert(tag);
	return packet_mgr->GetComponentName(tag).c_str();
	}

bool Analyzer::IsAnalyzer(const char* name)
	{
	assert(tag);
	return packet_mgr->GetComponentName(tag) == name;
	}

AnalyzerPtr Analyzer::Lookup(uint32_t identifier) const
	{
	return dispatcher.Lookup(identifier);
	}

bool Analyzer::ForwardPacket(size_t len, const uint8_t* data, Packet* packet,
                             uint32_t identifier) const
	{
	auto inner_analyzer = Lookup(identifier);
	if ( ! inner_analyzer )
		inner_analyzer = default_analyzer;

	if ( inner_analyzer == nullptr )
		{
		DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s failed, could not find analyzer for identifier %#x.",
				GetAnalyzerName(), identifier);
		packet_mgr->ReportUnknownProtocol(GetAnalyzerName(), identifier, data, len);
		return false;
		}

	DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s succeeded, next layer identifier is %#x.",
			GetAnalyzerName(), identifier);
	return inner_analyzer->AnalyzePacket(len, data, packet);
	}

bool Analyzer::ForwardPacket(size_t len, const uint8_t* data, Packet* packet) const
	{
	if ( default_analyzer )
		return default_analyzer->AnalyzePacket(len, data, packet);

	DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s stopped, no default analyzer available.",
			GetAnalyzerName());

	Weird("no_suitable_analyzer_found", packet);
	return true;
	}

void Analyzer::DumpDebug() const
	{
#ifdef DEBUG
	DBG_LOG(DBG_PACKET_ANALYSIS, "Dispatcher for %s", this->GetAnalyzerName());
	dispatcher.DumpDebug();
#endif
	}

void Analyzer::RegisterProtocol(uint32_t identifier, AnalyzerPtr child)
	{
	if ( run_state::detail::zeek_init_done )
		reporter->FatalError("Packet protocols cannot be registered after zeek_init has finished.");

	dispatcher.Register(identifier, std::move(child));
	}

void Analyzer::Weird(const char* name, Packet* packet, const char* addl) const
	{
	session_mgr->Weird(name, packet, addl, GetAnalyzerName());
	}

} // namespace zeek::packet_analysis
