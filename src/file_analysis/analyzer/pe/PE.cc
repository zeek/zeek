#include "PE.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

PE::PE(zeek::IntrusivePtr<RecordVal> args, File* file)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("PE"), std::move(args),
                              file)
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

bool PE::DeliverStream(const u_char* data, uint64_t len)
	{
	if ( conn->is_done() )
		return false;

	try
		{
		interp->NewData(data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		return false;
		}

	return ! conn->is_done();
	}

bool PE::EndOfFile()
	{
	return false;
	}
