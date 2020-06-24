// See the file "COPYING" in the main distribution directory for copyright.

#include "Unified2.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

Unified2::Unified2(zeek::IntrusivePtr<RecordVal> args, File* file)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("UNIFIED2"), std::move(args), file)
	{
	interp = new binpac::Unified2::Unified2_Analyzer(this);
	}

Unified2::~Unified2()
	{
	delete interp;
	}

file_analysis::Analyzer* Unified2::Instantiate(zeek::IntrusivePtr<RecordVal> args, File* file)
	{
	return new Unified2(std::move(args), file);
	}

bool Unified2::DeliverStream(const u_char* data, uint64_t len)
	{
	try
		{
		interp->NewData(true, data, data + len);
		}

	catch ( const binpac::Exception& e )
		{
		printf("Binpac exception: %s\n", e.c_msg());
		return false;
		}

	return true;
	}
