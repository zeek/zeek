// See the file "COPYING" in the main distribution directory for copyright.

#include "Analyzer.h"

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

bool Analyzer::RegisterAnalyzerMapping(uint32_t identifier, AnalyzerPtr analyzer)
	{
	return dispatcher.Register(identifier, std::move(analyzer));
	}

void Analyzer::RegisterDefaultAnalyzer(AnalyzerPtr default_analyzer)
	{
	this->default_analyzer = std::move(default_analyzer);
	}

AnalyzerPtr Analyzer::Lookup(uint32_t identifier) const
	{
	return dispatcher.Lookup(identifier);
	}

AnalyzerResult Analyzer::AnalyzeInnerPacket(Packet* packet,
		const uint8_t*& data, uint32_t identifier) const
	{
	auto inner_analyzer = Lookup(identifier);
	inner_analyzer = inner_analyzer ? inner_analyzer : default_analyzer;

	if ( inner_analyzer == nullptr )
		{
		DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s failed, could not find analyzer for identifier %#x.",
				GetAnalyzerName(), identifier);
		packet->Weird("no_suitable_analyzer_found");
		return AnalyzerResult::Failed;
		}

	DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s succeeded, next layer identifier is %#x.",
			GetAnalyzerName(), identifier);
	return inner_analyzer->Analyze(packet, data);
	}

}