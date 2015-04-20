#include "PE.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

PE::PE(RecordVal* args, File* file)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("PE"), args, file)
	{
	conn = new binpac::PE::MockConnection(this);
	interp = new binpac::PE::File(conn);
	done = false;
	}

PE::~PE()
	{
	delete interp;
	delete conn;
	}

bool PE::DeliverStream(const u_char* data, uint64 len)
	{
	if ( conn->is_done() )
		return true;
	try
		{
		interp->NewData(data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		return false;
		}

	return true;
	}

bool PE::EndOfFile()
	{
	return false;
	}
