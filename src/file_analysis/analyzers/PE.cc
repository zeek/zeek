#include <string>

#include "PE.h"
#include "pe_pac.h"
#include "util.h"
#include "Event.h"

using namespace file_analysis;

PE_Analyzer::PE_Analyzer(RecordVal* args, File* file)
    : Action(args, file)
	{
	conn = new binpac::PE::MockConnection(this);
	interp = new binpac::PE::File(conn);
	done=false;
	}

PE_Analyzer::~PE_Analyzer()
	{
	delete interp;
	}

Action* PE_Analyzer::Instantiate(RecordVal* args, File* file)
	{
	return new PE_Analyzer(args, file);
	}

bool PE_Analyzer::DeliverStream(const u_char* data, uint64 len)
	{
	printf("deliver stream\n");
	if (done)
	{
		printf("analyzer done\n");
		return false;
	}

	Action::DeliverStream(data, len);
	try
		{
		interp->NewData(data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		printf("Binpac exception: %s\n", e.c_msg());
		return false;
		}

	return true;
	}

bool PE_Analyzer::EndOfFile()
	{
	printf("end of file!\n");
	done=true;
	return false;
	}
