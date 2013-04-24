#ifndef FILE_ANALYSIS_PE_H
#define FILE_ANALYSIS_PE_H

#include <string>

#include "Val.h"
#include "../File.h"
#include "pe_pac.h"

namespace file_analysis {

/**
 * An action to simply extract files to disk.
 */
class PE_Analyzer : Action {
public:
	static Action* Instantiate(RecordVal* args, File* file);

	~PE_Analyzer();

	virtual bool DeliverStream(const u_char* data, uint64 len);

	virtual bool EndOfFile();

protected:
	PE_Analyzer(RecordVal* args, File* file);
	binpac::PE::File* interp;
	binpac::PE::MockConnection* conn;
	bool done;
};

} // namespace file_analysis

#endif
