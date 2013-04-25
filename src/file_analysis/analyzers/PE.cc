#include <string>

#include "PE.h"
#include "pe_pac.h"
#include "util.h"
#include "Event.h"

using namespace file_analysis;

PE::PE(RecordVal* args, File* file)
    : file_analysis::Analyzer(args, file)
	{
	conn = new binpac::PE::MockConnection(this);
	interp = new binpac::PE::File(conn);
	done=false;
	}

PE::~PE()
	{
	delete interp;
	}

bool PE::DeliverStream(const u_char* data, uint64 len)
	{
	try
		{
		interp->NewData(data, data + len);
		}
	catch ( const binpac::HaltParser &e )
		{
		return false;
		}
	catch ( const binpac::Exception& e )
		{
		printf("Binpac exception: %s\n", e.c_msg());
		return false;
		}

	return true;
	}

bool PE::EndOfFile()
	{
	printf("end of file!\n");
	//throw binpac::HaltParser();
	return false;
	}
