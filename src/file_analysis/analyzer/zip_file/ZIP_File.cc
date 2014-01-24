// See the file "COPYING" in the main distribution directory for copyright.

#include "ZIP_File.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

ZIP_File::ZIP_File(RecordVal* args, File* file)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("ZIP"), args, file)
	{
	interp = new binpac::ZIP_File::ZIP_File_Analyzer(this);
	}

ZIP_File::~ZIP_File()
	{
	delete interp;
	}

file_analysis::Analyzer* ZIP_File::Instantiate(RecordVal* args, File* file)
	{
	return new ZIP_File(args, file);
	}

bool ZIP_File::DeliverStream(const u_char* data, uint64 len)
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
