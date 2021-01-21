// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char

#include "zeek/file_analysis/Tag.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(RecordVal, zeek);
namespace zeek {
using RecordValPtr = IntrusivePtr<RecordVal>;
}

ZEEK_FORWARD_DECLARE_NAMESPACED(File, zeek, file_analysis);

namespace zeek::file_analysis {

using ID = uint32_t;

/**
 * Base class for analyzers that can be attached to file_analysis::File objects.
 */
class Analyzer {
public:

	/**
	 * Destructor.  Nothing special about it. Virtual since we definitely expect
	 * to delete instances of derived classes via pointers to this class.
	 */
	virtual ~Analyzer();

	/**
	 * Initializes the analyzer before input processing starts.
	 */
	virtual void Init()
		{ }

	/**
	 * Finishes the analyzer's operation after all input has been parsed.
	 */
	virtual void Done()
		{ }

	/**
	 * Subclasses may override this method to receive file data non-sequentially.
	 * @param data points to start of a chunk of file data.
	 * @param len length in bytes of the chunk of data pointed to by \a data.
	 * @param offset the byte offset within full file that data chunk starts.
	 * @return true if the analyzer is still in a valid state to continue
	 *         receiving data/events or false if it's essentially "done".
	 */
	virtual bool DeliverChunk(const u_char* data, uint64_t len, uint64_t offset)
		{ return true; }

	/**
	 * Subclasses may override this method to receive file sequentially.
	 * @param data points to start of the next chunk of file data.
	 * @param len length in bytes of the chunk of data pointed to by \a data.
	 * @return true if the analyzer is still in a valid state to continue
	 *         receiving data/events or false if it's essentially "done".
	 */
	virtual bool DeliverStream(const u_char* data, uint64_t len)
		{ return true; }

	/**
	 * Subclasses may override this method to specifically handle an EOF signal,
	 * which means no more data is going to be incoming and the analyzer
	 * may be deleted/cleaned up soon.
	 * @return true if the analyzer is still in a valid state to continue
	 *         receiving data/events or false if it's essentially "done".
	 */
	virtual bool EndOfFile()
		{ return true; }

	/**
	 * Subclasses may override this method to handle missing data in a file.
	 * @param offset the byte offset within full file at which the missing
	 *        data chunk occurs.
	 * @param len the number of missing bytes.
	 * @return true if the analyzer is still in a valid state to continue
	 *         receiving data/events or false if it's essentially "done".
	 */
	virtual bool Undelivered(uint64_t offset, uint64_t len)
		{ return true; }

	/**
	 * @return the analyzer type enum value.
	 */
	file_analysis::Tag Tag() const { return tag; }

	/**
	 * Returns the analyzer instance's internal ID. These IDs are unique
	 * across all analyzers instantiated and can thus be used to
	 * indentify a specific instance.
	 */
	ID GetID() const	{ return id; }

	/**
	 * @return the AnalyzerArgs associated with the analyzer.
	 */
	const RecordValPtr& GetArgs() const
		{ return args; }

	/**
	 * @return the file_analysis::File object to which the analyzer is attached.
	 */
	File* GetFile() const { return file; }

	/**
	 * Sets the tag associated with the analyzer's type. Note that this
	 * can be called only right after construction, if the constructor
	 * did not receive a name or tag. The method cannot be used to change
	 * an existing tag.
	 */
	void SetAnalyzerTag(const file_analysis::Tag& tag);

	/**
	 * @return true if the analyzer has ever seen a stream-wise delivery.
	 */
	bool GotStreamDelivery() const
		{ return got_stream_delivery; }

	/**
	 * Flag the analyzer as having seen a stream-wise delivery.
	 */
	void SetGotStreamDelivery()
		{ got_stream_delivery = true; }

	/**
	 * Signals that the analyzer is to skip all further input
	 * processsing. This won't have an immediate effect internally, but
	 * the flag can be queried through Skipping().
	 *
	 * @param do_skip If true, further processing will be skipped.
	 */
	void SetSkip(bool do_skip)		{ skip = do_skip; }

	/**
	 * Returns true if the analyzer has been told to skip processing all
	 * further input.
	 */
	bool Skipping() const			{ return skip; }

protected:

	/**
	 * Constructor.  Only derived classes are meant to be instantiated.
	 * @param arg_tag the tag definining the analyzer's type.
	 * @param arg_args an \c AnalyzerArgs (script-layer type) value specifiying
	 *        tunable options, if any, related to a particular analyzer type.
	 * @param arg_file the file to which the the analyzer is being attached.
	 */
	Analyzer(file_analysis::Tag arg_tag, RecordValPtr arg_args, File* arg_file);

	/**
	 * Constructor.  Only derived classes are meant to be instantiated.
	 * As this version of the constructor does not receive a name or tag,
	 * SetAnalyzerTag() must be called before the instance can be used.
	 *
	 * @param arg_args an \c AnalyzerArgs (script-layer type) value specifiying
	 *        tunable options, if any, related to a particular analyzer type.
	 * @param arg_file the file to which the the analyzer is being attached.
	 */
	Analyzer(RecordValPtr arg_args, File* arg_file);

private:

	ID id;	/**< Unique instance ID. */
	file_analysis::Tag tag;	/**< The particular type of the analyzer instance. */
	RecordValPtr args;	/**< \c AnalyzerArgs val gives tunable analyzer params. */
	File* file;	/**< The file to which the analyzer is attached. */
	bool got_stream_delivery;
	bool skip;

	static ID id_counter;
};

} // namespace zeek::file_analysis
