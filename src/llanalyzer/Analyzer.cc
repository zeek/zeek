// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>
#include "Analyzer.h"

namespace zeek::llanalyzer {

Analyzer::Analyzer(std::string name)
	{
	Tag t = llanalyzer_mgr->GetComponentTag(name);

	if ( ! t )
		reporter->InternalError("unknown llanalyzer name %s", name.c_str());

	Init(t);
	}

Analyzer::Analyzer(const Tag& tag)
	{
	Init(tag);
	}

/* PRIVATE */
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
	return llanalyzer_mgr->GetComponentName(tag).c_str();
	}

bool Analyzer::IsAnalyzer(const char* name)
	{
	assert(tag);
	return llanalyzer_mgr->GetComponentName(tag).compare(name) == 0;
	}

}
