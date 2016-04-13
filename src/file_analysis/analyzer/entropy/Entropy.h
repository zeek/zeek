// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_ENTROPY_H
#define FILE_ANALYSIS_ENTROPY_H

#include <string>

#include "Val.h"
#include "OpaqueVal.h"
#include "File.h"
#include "Analyzer.h"

#include "events.bif.h"

namespace file_analysis {

/**
 * An analyzer to produce a hash of file contents.
 */
class Entropy : public file_analysis::Analyzer {
public:

	/**
	 * Destructor.
	 */
	virtual ~Entropy();

	/**
	 * Create a new instance of an Extract analyzer.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @return the new Extract analyzer instance or a null pointer if the
	 *         the "extraction_file" field of \a args wasn't set.
	 */
	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file);

	/**
	 * Incrementally hash next chunk of file contents.
	 * @param data pointer to start of a chunk of a file data.
	 * @param len number of bytes in the data chunk.
	 * @return false if the digest is in an invalid state, else true.
	 */
	virtual bool DeliverStream(const u_char* data, uint64 len);

	/**
	 * Finalizes the hash and raises a "file_entropy_test" event.
	 * @return always false so analyze will be deteched from file.
	 */
	virtual bool EndOfFile();

	/**
	 * Missing data can't be handled, so just indicate the this analyzer should
	 * be removed from receiving further data.  The hash will not be finalized.
	 * @param offset byte offset in file at which missing chunk starts.
	 * @param len number of missing bytes.
	 * @return always false so analyzer will detach from file.
	 */
	virtual bool Undelivered(uint64 offset, uint64 len);

protected:

	/**
	 * Constructor.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @param hv specific hash calculator object.
	 * @param kind human readable name of the hash algorithm to use.
	 */
	Entropy(RecordVal* args, File* file);

	/**
	 * If some file contents have been seen, finalizes the hash of them and
	 * raises the "file_hash" event with the results.
	 */
	void Finalize();

private:
	EntropyVal* entropy;
	bool fed;
};

} // namespace file_analysis

#endif
