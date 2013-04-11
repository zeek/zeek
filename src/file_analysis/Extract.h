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

	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file);

	virtual ~Extract();

	virtual bool DeliverChunk(const u_char* data, uint64 len, uint64 offset);

protected:

	Extract(RecordVal* args, File* file, const string& arg_filename);

	string filename;
	int fd;
};

} // namespace file_analysis

#endif
