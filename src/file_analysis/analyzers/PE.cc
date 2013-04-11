#include <string>

#include "PE.h"
#include "pe_pac.h"
#include "util.h"

using namespace file_analysis;

PE_Analyzer::PE_Analyzer(RecordVal* args, Info* info)
    : Action(args, info)
	{
	conn = new binpac::PE::MockConnection(this);
	interp = new binpac::PE::File(conn);
	}

PE_Analyzer::~PE_Analyzer()
	{
	delete interp;
	}

Action* PE_Analyzer::Instantiate(RecordVal* args, Info* info)
	{
	using BifType::Record::FileAnalysis::Info;
	//const char* field = "total_bytes";
	//Val* filesize = info->GetVal()->Lookup(Info->FieldOffset(field));
	//if ( ! filesize ) 
	//	// TODO: this should be a reporter message? or better yet stop relying on the file size.
	//	return 0;
//
	//bro_uint_t fsize = filesize->AsCount();
	return new PE_Analyzer(args, info);
	}

bool PE_Analyzer::DeliverStream(const u_char* data, uint64 len)
	{
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
