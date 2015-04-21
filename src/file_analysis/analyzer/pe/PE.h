#ifndef FILE_ANALYSIS_PE_H
#define FILE_ANALYSIS_PE_H

#include <string>

#include "Val.h"
#include "../File.h"
#include "pe_pac.h"

namespace file_analysis {

/**
 * Analyze Portable Executable files
 */
class PE : public file_analysis::Analyzer {
public:
	~PE();

	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file)
		{ return new PE(args, file); }

	virtual bool DeliverStream(const u_char* data, uint64 len);

	virtual bool EndOfFile();

protected:
	PE(RecordVal* args, File* file);
	binpac::PE::File* interp;
	binpac::PE::MockConnection* conn;
	bool done;
};

} // namespace file_analysis

#endif
