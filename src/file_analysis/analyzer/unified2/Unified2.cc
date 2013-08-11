// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "Unified2.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

Unified2::Unified2(RecordVal* args, File* file)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("UNIFIED2"), args, file)
	{
	interp = new binpac::Unified2::Unified2_Analyzer(this);
	}

Unified2::~Unified2()
	{
	}

file_analysis::Analyzer* Unified2::Instantiate(RecordVal* args, File* file)
	{
	return new Unified2(args, file);
	}

bool Unified2::DeliverStream(const u_char* data, uint64 len)
	{
	interp->NewData(true, data, data+len);
	return true;
	}
