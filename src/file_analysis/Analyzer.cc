// See the file "COPYING" in the main distribution directory for copyright.

#include "Analyzer.h"
#include "Manager.h"

file_analysis::ID file_analysis::Analyzer::id_counter = 0;

file_analysis::Analyzer::~Analyzer()
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "Destroy file analyzer %s",
	        file_mgr->GetComponentName(tag).c_str());
	Unref(args);
	}

void file_analysis::Analyzer::SetAnalyzerTag(const file_analysis::Tag& arg_tag)
	{
	assert(! tag || tag == arg_tag);
	tag = arg_tag;
	}
