// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_UNIFIED2_H
#define FILE_ANALYSIS_UNIFIED2_H

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
	virtual ~Unified2();

	virtual bool DeliverStream(const u_char* data, uint64 len);

	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file);

protected:
	Unified2(RecordVal* args, File* file);

private:
	binpac::Unified2::Unified2_Analyzer* interp;

	string filename;
};

} // namespace file_analysis

#endif
