#pragma once

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

	static file_analysis::Analyzer* Instantiate(zeek::RecordValPtr args,
	                                            File* file)
		{ return new PE(std::move(args), file); }

	virtual bool DeliverStream(const u_char* data, uint64_t len);

	virtual bool EndOfFile();

protected:
	PE(zeek::RecordValPtr args, File* file);
	binpac::PE::File* interp;
	binpac::PE::MockConnection* conn;
	bool done;
};

} // namespace file_analysis
