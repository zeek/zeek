// See the file "COPYING" in the main distribution directory for copyright.
//
// Class for managing input streams.

#pragma once

#include <map>

#include "zeek/EventHandler.h"
#include "zeek/Tag.h"
#include "zeek/input/Component.h"
#include "zeek/plugin/ComponentManager.h"
#include "zeek/threading/SerialTypes.h"

namespace zeek
	{

class RecordVal;

namespace input
	{

class ReaderFrontend;
class ReaderBackend;

/**
 * Singleton class for managing input streams.
 */
class Manager : public plugin::ComponentManager<Component>
	{
public:
	/**
	 * Constructor.
	 */
	Manager();

	/**
	 * Destructor.
	 */
	~Manager();

	/**
	 * Creates a new input stream which will write the data from the data
	 * source into a table.
	 *
	 * @param description A record of script type \c
	 * Input:StreamDescription.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * input.bif, which just forwards here.
	 */
	bool CreateTableStream(RecordVal* description);

	/**
	 * Creates a new input stream which sends events for read input data.
	 *
	 * @param description A record of script type \c
	 * Input:StreamDescription.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * input.bif, which just forwards here.
	 */
	bool CreateEventStream(RecordVal* description);

	/**
	 * Creates a new input stream which will forward the data from the data
	 * source on to the file analysis framework.  The internal BiF defined
	 * in input.bif just forward here.  For an input reader to be compatible
	 * with this method, it must be able to accept a filter of a single string
	 * type (i.e. they read a byte stream).
	 *
	 * @param description A record of the script type \c
	 * Input::AnalysisDescription
	 */
	bool CreateAnalysisStream(RecordVal* description);

	/**
	 * Force update on a input stream. Forces a re-read of the whole
	 * input source. Usually used when an input stream is opened in
	 * managed mode. Otherwise, this can be used to trigger a input
	 * source check before a heartbeat message arrives. May be ignored by
	 * the reader.
	 *
	 * @param id The enum value corresponding the input stream.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * input.bif, which just forwards here.
	 */
	bool ForceUpdate(const std::string& id);

	/**
	 * Deletes an existing input stream.
	 *
	 * @param id The name of the input stream to be removed.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * input.bif, which just forwards here.
	 */
	bool RemoveStream(const std::string& id);

	/**
	 * Signals the manager to shutdown at Zeek's termination.
	 */
	void Terminate();

	/**
	 * Checks if a Zeek type can be used for data reading. Note that
	 * this function only applies to input streams; the logging framework
	 * has an equivalent function; however we support logging of a wider
	 * variety of types (e.g. functions).
	 *
	 * @param t The type to check.
	 *
	 * @param atomic_only Set to true to forbid non-atomic types
	 *        (records/sets/vectors).
	 *
	 * @return True if the type is compatible with the input framework.
	 */
	static bool IsCompatibleType(Type* t, bool atomic_only = false);

protected:
	friend class ReaderFrontend;
	friend class PutMessage;
	friend class DeleteMessage;
	friend class ClearMessage;
	friend class SendEntryMessage;
	friend class EndCurrentSendMessage;
	friend class ReaderClosedMessage;
	friend class DisableMessage;
	friend class EndOfDataMessage;
	friend class ReaderErrorMessage;

	// For readers to write to input stream in direct mode (reporting
	// new/deleted values directly). Functions take ownership of
	// threading::Value fields.
	void Put(ReaderFrontend* reader, threading::Value** vals);
	void Clear(ReaderFrontend* reader);
	bool Delete(ReaderFrontend* reader, threading::Value** vals);
	// Trigger sending the End-of-Data event when the input source has
	// finished reading. Just use in direct mode.
	void SendEndOfData(ReaderFrontend* reader);

	// For readers to write to input stream in indirect mode (manager is
	// monitoring new/deleted values) Functions take ownership of
	// threading::Value fields.
	void SendEntry(ReaderFrontend* reader, threading::Value** vals);
	void EndCurrentSend(ReaderFrontend* reader);

	// Instantiates a new ReaderBackend of the given type (note that
	// doing so creates a new thread!).
	ReaderBackend* CreateBackend(ReaderFrontend* frontend, EnumVal* tag);

	// Function called from the ReaderBackend to notify the manager that
	// a stream has been removed or a stream has been closed. Used to
	// prevent race conditions where data for a specific stream is still
	// in the queue when the RemoveStream directive is executed by the
	// main thread. This makes sure all data that has ben queued for a
	// stream is still received.
	bool RemoveStreamContinuation(ReaderFrontend* reader);

	// Signal Informational messages, warnings and errors. These will be
	// passed to the error function in scriptland. Note that the messages
	// are not passed to reporter - this is done in ReaderBackend.
	void Info(ReaderFrontend* reader, const char* msg) const;
	void Warning(ReaderFrontend* reader, const char* msg) const;
	void Error(ReaderFrontend* reader, const char* msg) const;

	/**
	 * Deletes an existing input stream.
	 *
	 * @param frontend pointer to the frontend of the input stream to be removed.
	 *
	 * This method is used by the reader backends to remove a reader when it fails
	 * for some reason.
	 */
	bool RemoveStream(ReaderFrontend* frontend);

private:
	class Stream;
	class TableStream;
	class EventStream;
	class AnalysisStream;

	// Actual RemoveStream implementation -- the function's public and
	// protected definitions are wrappers around this function.
	bool RemoveStream(Stream* i);

	bool CreateStream(Stream*, RecordVal* description);

	// Check if the types of the error_ev event are correct. If table is
	// true, check for tablestream type, otherwise check for eventstream
	// type.
	bool CheckErrorEventTypes(const std::string& stream_name, const Func* error_event,
	                          bool table) const;

	// SendEntry implementation for Table stream.
	int SendEntryTable(Stream* i, const threading::Value* const* vals);

	// Put implementation for Table stream.
	int PutTable(Stream* i, const threading::Value* const* vals);

	// SendEntry and Put implementation for Event stream.
	int SendEventStreamEvent(Stream* i, EnumVal* type, const threading::Value* const* vals);

	// Check if a record is made up of compatible types and return a list
	// of all fields that are in the record in order. Recursively unrolls
	// records
	bool UnrollRecordType(std::vector<threading::Field*>* fields, const RecordType* rec,
	                      const std::string& nameprepend, bool allow_file_func) const;

	// Send events
	void SendEvent(EventHandlerPtr ev, const int numvals, ...) const;
	void SendEvent(EventHandlerPtr ev, std::list<Val*> events) const;

	// Implementation of SendEndOfData (send end_of_data event).
	void SendEndOfData(const Stream* i);

	// Call predicate function and return result.
	bool CallPred(Func* pred_func, const int numvals, ...) const;

	// Get a hashkey for a set of threading::Values.
	zeek::detail::HashKey* HashValues(const int num_elements,
	                                  const threading::Value* const* vals) const;

	// Get the memory used by a specific value.
	int GetValueLength(const threading::Value* val) const;

	// Copies the raw data in a specific threading::Value to position
	// startpos.
	int CopyValue(char* data, const int startpos, const threading::Value* val) const;

	// Convert Threading::Value to an internal Zeek Type (works with Records).
	Val* ValueToVal(const Stream* i, const threading::Value* val, Type* request_type,
	                bool& have_error) const;

	// Convert Threading::Value to an internal Zeek list type.
	Val* ValueToIndexVal(const Stream* i, int num_fields, const RecordType* type,
	                     const threading::Value* const* vals, bool& have_error) const;

	// Converts a threading::value to a record type. Mostly used by
	// ValueToVal.
	RecordVal* ValueToRecordVal(const Stream* i, const threading::Value* const* vals,
	                            RecordType* request_type, int* position, bool& have_error) const;

	Val* RecordValToIndexVal(RecordVal* r) const;

	// Converts a Zeek ListVal to a RecordVal given the record type.
	RecordVal* ListValToRecordVal(ListVal* list, RecordType* request_type, int* position) const;

	// Internally signal errors, warnings, etc.
	// These are sent on to input scriptland and reporter.log
	void Info(const Stream* i, const char* fmt, ...) const __attribute__((format(printf, 3, 4)));
	void Warning(const Stream* i, const char* fmt, ...) const __attribute__((format(printf, 3, 4)));
	void Error(const Stream* i, const char* fmt, ...) const __attribute__((format(printf, 3, 4)));

	enum class ErrorType
		{
		INFO,
		WARNING,
		ERROR
		};
	void ErrorHandler(const Stream* i, ErrorType et, bool reporter_send, const char* fmt, ...) const
		__attribute__((format(printf, 5, 6)));
	void ErrorHandler(const Stream* i, ErrorType et, bool reporter_send, const char* fmt,
	                  va_list ap) const __attribute__((format(printf, 5, 0)));

	Stream* FindStream(const std::string& name) const;
	Stream* FindStream(ReaderFrontend* reader) const;

	enum StreamType
		{
		TABLE_STREAM,
		EVENT_STREAM,
		ANALYSIS_STREAM
		};

	std::map<ReaderFrontend*, Stream*> readers;

	EventHandlerPtr end_of_data;
	};

	} // namespace input

extern input::Manager* input_mgr;

	} // namespace zeek
