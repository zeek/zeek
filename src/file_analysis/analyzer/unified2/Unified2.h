// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>

#include "Val.h"
#include "File.h"
#include "Analyzer.h"
#include "unified2_pac.h"

namespace file_analysis {

/**
 * An analyzer to extract content of files from local disk.
 */
class Unified2 : public file_analysis::Analyzer {
public:
	~Unified2() override;

	bool DeliverStream(const u_char* data, uint64_t len) override;

	static file_analysis::Analyzer* Instantiate(zeek::IntrusivePtr<RecordVal> args,
	                                            File* file);

protected:
	Unified2(zeek::IntrusivePtr<RecordVal> args, File* file);

private:
	binpac::Unified2::Unified2_Analyzer* interp;

	string filename;
};

} // namespace file_analysis
