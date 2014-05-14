// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_FILE_H
#define FILE_ANALYSIS_FILE_H

#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "Conn.h"
#include "Val.h"
#include "Tag.h"
#include "AnalyzerSet.h"
#include "BroString.h"

namespace file_analysis {

/**
 * Wrapper class around \c fa_file record values from script layer.
 */
class File {
public:

	/**
	 * Destructor.  Nothing fancy, releases a reference to the wrapped
	 * \c fa_file value.
	 */
	~File();

	/**
	 * @return the wrapped \c fa_file record value, #val.
	 */
	RecordVal* GetVal() const { return val; }

	/**
	 * @return the value of the "source" field from #val record or an empty
	 * string if it's not initialized.
	 */
	string GetSource() const;

	/**
	 * Set the "source" field from #val record to \a source.
	 * @param source the new value of the "source" field.
	 */
	void SetSource(const string& source);

	/**
	 * @return value (seconds) of the "timeout_interval" field from #val record.
	 */
	double GetTimeoutInterval() const;

	/**
	 * Set the "timeout_interval" field from #val record to \a interval seconds.
	 * @param interval the new value of the "timeout_interval" field.
	 */
	void SetTimeoutInterval(double interval);

	/**
	 * Change the maximum size that an attached extraction analyzer is allowed.
	 * @param args the file extraction analyzer whose limit needs changed.
	 * @param bytes new limit.
	 * @return false if no extraction analyzer is active, else true.
	 */
	bool SetExtractionLimit(RecordVal* args, uint64 bytes);

	/**
	 * @return value of the "id" field from #val record.
	 */
	string GetID() const { return id; }

	/**
	 * @return value of "last_active" field in #val record;
	 */
	double GetLastActivityTime() const;

	/**
	 * Refreshes "last_active" field of #val record with current network time.
	 */
	void UpdateLastActivityTime();

	/**
	 * Set "total_bytes" field of #val record to \a size.
	 * @param size the new value of the "total_bytes" field.
	 */
	void SetTotalBytes(uint64 size);

	/**
	 * Compares "seen_bytes" field to "total_bytes" field of #val record to
	 * determine if the full file has been seen.
	 * @return false if "total_bytes" hasn't been set yet or "seen_bytes" is
	 *         less than it, else true.
	 */
	bool IsComplete() const;

	/**
	 * Create a timer to be dispatched after the amount of time indicated by
	 * the "timeout_interval" field of the #val record in order to check if
	 * "last_active" field is old enough to timeout analysis of the file.
	 */
	void ScheduleInactivityTimer() const;

	/**
	 * Queues attaching an analyzer.  Only one analyzer per type can be attached
	 * at a time unless the arguments differ.
	 * @param tag the analyzer tag of the file analyzer to add.
	 * @param args an \c AnalyzerArgs value representing a file analyzer.
	 * @return false if analyzer can't be instantiated, else true.
	 */
	bool AddAnalyzer(file_analysis::Tag tag, RecordVal* args);

	/**
	 * Queues removal of an analyzer.
	 * @param tag the analyzer tag of the file analyzer to remove.
	 * @param args an \c AnalyzerArgs value representing a file analyzer.
	 * @return true if analyzer was active at time of call, else false.
	 */
	bool RemoveAnalyzer(file_analysis::Tag tag, RecordVal* args);

	/**
	 * Pass in non-sequential data and deliver to attached analyzers.
	 * @param data pointer to start of a chunk of file data.
	 * @param len number of bytes in the data chunk.
	 * @param offset number of bytes from start of file at which chunk occurs.
	 */
	void DataIn(const u_char* data, uint64 len, uint64 offset);

	/**
	 * Pass in sequential data and deliver to attached analyzers.
	 * @param data pointer to start of a chunk of file data.
	 * @param len number of bytes in the data chunk.
	 */
	void DataIn(const u_char* data, uint64 len);

	/**
	 * Inform attached analyzers about end of file being seen.
	 */
	void EndOfFile();

	/**
	 * Inform attached analyzers about a gap in file stream.
	 * @param offset number of bytes in to file at which missing chunk starts.
	 * @param len length in bytes of the missing chunk of file data.
	 */
	void Gap(uint64 offset, uint64 len);

	/**
	 * @param h pointer to an event handler.
	 * @return true if event has a handler and the file isn't ignored.
	 */
	bool FileEventAvailable(EventHandlerPtr h);

	/**
	 * Raises an event related to the file's life-cycle, the only parameter
	 * to that event is the \c fa_file record..
	 * @param h pointer to an event handler.
	 */
	void FileEvent(EventHandlerPtr h);

	/**
	 * Raises an event related to the file's life-cycle.
	 * @param h pointer to an event handler.
	 * @param vl list of argument values to pass to event call.
	 */
	void FileEvent(EventHandlerPtr h, val_list* vl);

protected:
	friend class Manager;

	/**
	 * Constructor; only file_analysis::Manager should be creating these.
	 * @param file_id an identifier string for the file in pretty hash form
	 *        (similar to connection uids).
	 * @param conn a network connection over which the file is transferred.
	 * @param tag the network protocol over which the file is transferred.
	 * @param is_orig true if the file is being transferred from the originator
	 *        of the connection to the responder.  False indicates the other
	 *        direction.
	 */
	File(const string& file_id, Connection* conn = 0,
	     analyzer::Tag tag = analyzer::Tag::Error, bool is_orig = false);

	/**
	 * Updates the "conn_ids" and "conn_uids" fields in #val record with the
	 * \c conn_id and UID taken from \a conn.
	 * @param conn the connection over which a part of the file has been seen.
	 * @param is_orig true if the connection originator is sending the file.
	 */
	void UpdateConnectionFields(Connection* conn, bool is_orig);

	/**
	 * Increment a byte count field of #val record by \a size.
	 * @param size number of bytes by which to increment.
	 * @param field_idx the index of the field in \c fa_file to increment.
	 */
	void IncrementByteCount(uint64 size, int field_idx);

	/**
	 * Wrapper to RecordVal::LookupWithDefault for the field in #val at index
	 * \a idx which automatically unrefs the Val and returns a converted value.
	 * @param idx the index of a field of type "count" in \c fa_file.
	 * @return the value of the field, which may be it &default.
	 */
	uint64 LookupFieldDefaultCount(int idx) const;

	/**
	 * Wrapper to RecordVal::LookupWithDefault for the field in #val at index
	 * \a idx which automatically unrefs the Val and returns a converted value.
	 * @param idx the index of a field of type "interval" in \c fa_file.
	 * @return the value of the field, which may be it &default.
	 */
	double LookupFieldDefaultInterval(int idx) const;

	/**
	 * Buffers incoming data at the beginning of a file.
	 * @param data pointer to a data chunk to buffer.
	 * @param len number of bytes in the data chunk.
	 * @return true if buffering is still required, else false
	 */
	bool BufferBOF(const u_char* data, uint64 len);

	/**
	 * Forward any beginning-of-file buffered data on to DataIn stream.
	 */
	void ReplayBOF();

	/**
	 * Does mime type detection via file magic signatures and assigns
	 * strongest matching mime type (if available) to \c mime_type
	 * field in #val.
	 * @param data pointer to a chunk of file data.
	 * @param len number of bytes in the data chunk.
	 * @return whether a mime type match was found.
	 */
	bool DetectMIME(const u_char* data, uint64 len);

	/**
	 * Lookup a record field index/offset by name.
	 * @param field_name the name of the \c fa_file record field.
	 * @return the field offset in #val record corresponding to \a field_name.
	 */
	static int Idx(const string& field_name);

	/**
	 * Initializes static member.
	 */
	static void StaticInit();

private:
	string id;                 /**< A pretty hash that likely identifies file */
	RecordVal* val;            /**< \c fa_file from script layer. */
	bool postpone_timeout;     /**< Whether postponing timeout is requested. */
	bool first_chunk;          /**< Track first non-linear chunk. */
	bool missed_bof;           /**< Flags that we missed start of file. */
	bool need_reassembly;      /**< Whether file stream reassembly is needed. */
	bool done;                 /**< If this object is about to be deleted. */
	bool did_file_new_event;   /**< Whether the file_new event has been done. */
	AnalyzerSet analyzers;     /**< A set of attached file analyzer. */
	queue<pair<EventHandlerPtr, val_list*> > fonc_queue;

	struct BOF_Buffer {
		BOF_Buffer() : full(false), replayed(false), size(0) {}
		~BOF_Buffer()
			{ for ( size_t i = 0; i < chunks.size(); ++i ) delete chunks[i]; }

		bool full;
		bool replayed;
		uint64 size;
		BroString::CVec chunks;
	} bof_buffer;              /**< Beginning of file buffer. */

	static int id_idx;
	static int parent_id_idx;
	static int source_idx;
	static int is_orig_idx;
	static int conns_idx;
	static int last_active_idx;
	static int seen_bytes_idx;
	static int total_bytes_idx;
	static int missing_bytes_idx;
	static int overflow_bytes_idx;
	static int timeout_interval_idx;
	static int bof_buffer_size_idx;
	static int bof_buffer_idx;
	static int mime_type_idx;
	static int mime_types_idx;
};

} // namespace file_analysis

#endif
