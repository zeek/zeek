// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>

#include "zeek/Val.h"
#include "zeek/file_analysis/File.h"
#include "zeek/file_analysis/Analyzer.h"
#include "file_analysis/analyzer/unified2/unified2_pac.h"

namespace zeek::file_analysis::detail {

/**
 * An analyzer to extract content of files from local disk.
 */
class Unified2 : public file_analysis::Analyzer {
public:
	~Unified2() override;

	bool DeliverStream(const u_char* data, uint64_t len) override;

	static file_analysis::Analyzer* Instantiate(RecordValPtr args,
	                                            file_analysis::File* file);

protected:
	Unified2(RecordValPtr args, file_analysis::File* file);

private:
	binpac::Unified2::Unified2_Analyzer* interp;

	string filename;
};

} // namespace zeek::file_analysis::detail
