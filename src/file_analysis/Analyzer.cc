// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/file_analysis/Analyzer.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/Val.h"

namespace zeek::file_analysis {

ID Analyzer::id_counter = 0;

Analyzer::~Analyzer()
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "Destroy file analyzer %s",
	        file_mgr->GetComponentName(tag).c_str());
	}

void Analyzer::SetAnalyzerTag(const file_analysis::Tag& arg_tag)
	{
	assert(! tag || tag == arg_tag);
	tag = arg_tag;
	}

Analyzer::Analyzer(file_analysis::Tag arg_tag,
                   RecordValPtr arg_args,
                   File* arg_file)
	: tag(arg_tag),
	  args(std::move(arg_args)),
	  file(arg_file),
	  got_stream_delivery(false),
	  skip(false)
	{
	id = ++id_counter;
	}

Analyzer::Analyzer(RecordValPtr arg_args, File* arg_file)
	: Analyzer({}, std::move(arg_args), arg_file)
	{}

} // namespace zeek::file_analysis
