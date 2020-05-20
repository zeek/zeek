// See the file "COPYING" in the main distribution directory for copyright.

#include "Analyzer.h"
#include "Manager.h"
#include "Val.h"

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

file_analysis::Analyzer::Analyzer(file_analysis::Tag arg_tag, RecordVal* arg_args, File* arg_file)
	: tag(arg_tag),
	  args(arg_args->Ref()->AsRecordVal()),
	  file(arg_file),
	  got_stream_delivery(false),
	  skip(false)
	{
	id = ++id_counter;
	}
