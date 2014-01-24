// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_ZIP_FILE_H
#define FILE_ANALYSIS_ZIP_FILE_H

#include <string>

#include "Val.h"
#include "File.h"
#include "Analyzer.h"
#include "zip_pac.h"

namespace file_analysis {

class ZIP_File : public file_analysis::Analyzer {
public:
	virtual ~ZIP_File();

	virtual bool DeliverStream(const u_char* data, uint64 len);

	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file);

protected:
	ZIP_File(RecordVal* args, File* file);

private:
	binpac::ZIP_File::ZIP_File_Analyzer* interp;

	string filename;
};

} // namespace file_analysis

#endif
