// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_EXTRACT_H
#define FILE_ANALYSIS_EXTRACT_H

#include <string>

#include "Val.h"
#include "File.h"
#include "Analyzer.h"

namespace file_analysis {

/**
 * An analyzer to extract files to disk.
 */
class Extract : public file_analysis::Analyzer {
public:
	virtual ~Extract();

	virtual bool DeliverChunk(const u_char* data, uint64 len, uint64 offset);

	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file);

protected:
	Extract(RecordVal* args, File* file, const string& arg_filename);

private:
	string filename;
	int fd;
};

} // namespace file_analysis

#endif
