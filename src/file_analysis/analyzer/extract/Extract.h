// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_EXTRACT_H
#define FILE_ANALYSIS_EXTRACT_H

#include <string>

#include "Val.h"
#include "File.h"
#include "Analyzer.h"

#include "analyzer/extract/events.bif.h"

namespace file_analysis {

/**
 * An analyzer to extract content of files to local disk.
 */
class Extract : public file_analysis::Analyzer {
public:

	/**
	 * Destructor.  Will close the file that was used for data extraction.
	 */
	virtual ~Extract();

	/**
	 * Write a chunk of file data to the local extraction file.
	 * @param data pointer to a chunk of file data.
	 * @param len number of bytes in the data chunk.
	 * @param offset number of bytes from start of file at which chunk starts.
	 * @return false if there was no extraction file open and the data couldn't
	 *         be written, else true.
	 */
	virtual bool DeliverChunk(const u_char* data, uint64 len, uint64 offset);

	/**
	 * Create a new instance of an Extract analyzer.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @return the new Extract analyzer instance or a null pointer if the
	 *         the "extraction_file" field of \a args wasn't set.
	 */
	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file);

	/**
	 * Sets the maximum allowed extracted file size.  A value of zero means
	 * "no limit".
	 * @param bytes number of bytes allowed to be extracted
	 */
	void SetLimit(uint64 bytes) { limit = bytes; }

protected:

	/**
	 * Constructor.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @param arg_filename a file system path which specifies the local file
	 *        to which the contents of the file will be extracted/written.
	 * @param arg_limit the maximum allowed file size.
	 */
	Extract(RecordVal* args, File* file, const string& arg_filename,
	        uint64 arg_limit);

private:
	string filename;
	int fd;
	uint64 limit;
};

} // namespace file_analysis

#endif
