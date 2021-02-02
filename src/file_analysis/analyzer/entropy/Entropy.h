// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>

#include "zeek/Val.h"
#include "zeek/OpaqueVal.h"
#include "zeek/file_analysis/File.h"
#include "zeek/file_analysis/Analyzer.h"

#include "file_analysis/analyzer/entropy/events.bif.h"

namespace zeek::file_analysis::detail {

/**
 * An analyzer to produce entropy of file contents.
 */
class Entropy : public file_analysis::Analyzer {
public:

	/**
	 * Destructor.
	 */
	~Entropy() override;

	/**
	 * Create a new instance of an Entropy analyzer.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @return the new Entropy analyzer instance or a null pointer if the
	 *         the "extraction_file" field of \a args wasn't set.
	 */
	static file_analysis::Analyzer* Instantiate(RecordValPtr args,
	                                            file_analysis::File* file);

	/**
	 * Calculate entropy of next chunk of file contents.
	 * @param data pointer to start of a chunk of a file data.
	 * @param len number of bytes in the data chunk.
	 * @return false if the digest is in an invalid state, else true.
	 */
	bool DeliverStream(const u_char* data, uint64_t len) override;

	/**
	 * Finalizes the calculation and raises a "file_entropy_test" event.
	 * @return always false so analyze will be detached from file.
	 */
	bool EndOfFile() override;

	/**
	 * Missing data can't be handled, so just indicate the this analyzer should
	 * be removed from receiving further data.  The entropy will not be finalized.
	 * @param offset byte offset in file at which missing chunk starts.
	 * @param len number of missing bytes.
	 * @return always false so analyzer will detach from file.
	 */
	bool Undelivered(uint64_t offset, uint64_t len) override;

protected:

	/**
	 * Constructor.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @param hv specific hash calculator object.
	 * @param kind human readable name of the hash algorithm to use.
	 */
	Entropy(RecordValPtr args, file_analysis::File* file);

	/**
	 * If some file contents have been seen, finalizes the entropy of them and
	 * raises the "file_entropy" event with the results.
	 */
	void Finalize();

private:
	EntropyVal* entropy;
	bool fed;
};

} // namespace zeek::file_analysis::detail
