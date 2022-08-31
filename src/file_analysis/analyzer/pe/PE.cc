#include "zeek/file_analysis/analyzer/pe/PE.h"

#include "zeek/file_analysis/Manager.h"

namespace zeek::file_analysis::detail
	{

PE::PE(RecordValPtr args, file_analysis::File* file)
	: file_analysis::Analyzer(file_mgr->GetComponentTag("PE"), std::move(args), file)
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
		AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
		return false;
		}

	return ! conn->is_done();
	}

bool PE::EndOfFile()
	{
	return false;
	}

	} // namespace zeek::file_analysis::detail
