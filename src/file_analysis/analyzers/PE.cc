#include <string>

#include "PE.h"
#include "pe_pac.h"
#include "util.h"

using namespace file_analysis;

PE_Analyzer::PE_Analyzer(Info* arg_info)
    : Action(arg_info)
	{
	interp = new binpac::PE::File(this);

	// Close the reverse flow.
	interp->FlowEOF(false);
	}

PE_Analyzer::~PE_Analyzer()
	{
	delete interp;
	}

Action* PE_Analyzer::Instantiate(const RecordVal* args, Info* info)
	{
	return new PE_Analyzer(info);
	}

void PE_Analyzer::DeliverStream(const u_char* data, uint64 len)
	{
	Action::DeliverStream(data, len);

	// Data is exclusively sent into the "up" flow.
	interp->NewData(true, data, data + len);
	}
