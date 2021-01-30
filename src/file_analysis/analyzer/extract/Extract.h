// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>

#include "zeek/Val.h"
#include "zeek/file_analysis/File.h"
#include "zeek/file_analysis/Analyzer.h"

#include "file_analysis/analyzer/extract/events.bif.h"

namespace zeek::file_analysis::detail {

/**
 * An analyzer to extract content of files to local disk.
 */
class Extract : public file_analysis::Analyzer {
public:

	/**
	 * Destructor.  Will close the file that was used for data extraction.
	 */
	~Extract() override;

	/**
	 * Write a chunk of file data to the local extraction file.
	 * @param data pointer to a chunk of file data.
	 * @param len number of bytes in the data chunk.
	 * @return false if there was no extraction file open and the data couldn't
	 *         be written, else true.
	 */
	bool DeliverStream(const u_char* data, uint64_t len) override;

	/**
	 * Report undelivered bytes.
	 * @param offset distance into the file where the gap occurred.
	 * @param len number of bytes undelivered.
	 * @return true
	 */
	bool Undelivered(uint64_t offset, uint64_t len) override;

	/**
	 * Create a new instance of an Extract analyzer.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @return the new Extract analyzer instance or a null pointer if the
	 *         the "extraction_file" field of \a args wasn't set.
	 */
	static file_analysis::Analyzer* Instantiate(RecordValPtr args,
	                                            file_analysis::File* file);

	/**
	 * Sets the maximum allowed extracted file size.  A value of zero means
	 * "no limit".
	 * @param bytes number of bytes allowed to be extracted
	 */
	void SetLimit(uint64_t bytes) { limit = bytes; }

protected:

	/**
	 * Constructor.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @param arg_filename a file system path which specifies the local file
	 *        to which the contents of the file will be extracted/written.
	 * @param arg_limit the maximum allowed file size.
	 */
	Extract(RecordValPtr args, file_analysis::File* file,
	        const std::string& arg_filename, uint64_t arg_limit);

private:
	std::string filename;
	int fd;
	uint64_t limit;
	uint64_t depth;
};

} // namespace zeek::file_analysis::detail
