// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>

#include "Val.h"
#include "File.h"
#include "Analyzer.h"
#include "unified2_pac.h"

namespace zeek::file_analysis::detail {

/**
 * An analyzer to extract content of files from local disk.
 */
class Unified2 : public zeek::file_analysis::Analyzer {
public:
	~Unified2() override;

	bool DeliverStream(const u_char* data, uint64_t len) override;

	static zeek::file_analysis::Analyzer* Instantiate(zeek::RecordValPtr args,
	                                                  zeek::file_analysis::File* file);

protected:
	Unified2(zeek::RecordValPtr args, zeek::file_analysis::File* file);

private:
	binpac::Unified2::Unified2_Analyzer* interp;

	string filename;
};

} // namespace zeek::file_analysis::detail

namespace file_analysis {

	using Unified2 [[deprecated("Remove in v4.1. Use zeek::file_analysis::detail::Unified2.")]] = zeek::file_analysis::detail::Unified2;

} // namespace file_analysis
