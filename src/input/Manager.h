// See the file "COPYING" in the main distribution directory for copyright.
//
// Class for managing input streams.

#ifndef INPUT_MANAGER_H
#define INPUT_MANAGER_H

#include "BroString.h"
#include "EventHandler.h"
#include "RemoteSerializer.h"
#include "Val.h"

#include <map>

namespace input {

class ReaderFrontend;
class ReaderBackend;

/**
 * Singleton class for managing input streams.
 */
class Manager {
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
	bool ForceUpdate(const string &id);

	/**
	 * Deletes an existing input stream.
	 *
	 * @param id The name of the input stream to be removed.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * input.bif, which just forwards here.
	 */
	bool RemoveStream(const string &id);

	/**
	 * Signals the manager to shutdown at Bro's termination.
	 */
	void Terminate();

protected:
	friend class ReaderFrontend;
	friend class PutMessage;
	friend class DeleteMessage;
	friend class ClearMessage;
	friend class SendEventMessage;
	friend class SendEntryMessage;
	friend class EndCurrentSendMessage;
	friend class ReaderClosedMessage;
	friend class DisableMessage;
	friend class EndOfDataMessage;

	// For readers to write to input stream in direct mode (reporting
	// new/deleted values directly). Functions take ownership of
	// threading::Value fields.
	void Put(ReaderFrontend* reader, threading::Value* *vals);
	void Clear(ReaderFrontend* reader);
	bool Delete(ReaderFrontend* reader, threading::Value* *vals);
	// Trigger sending the End-of-Data event when the input source has
	// finished reading. Just use in direct mode.
	void SendEndOfData(ReaderFrontend* reader);

	// For readers to write to input stream in indirect mode (manager is
	// monitoring new/deleted values) Functions take ownership of
	// threading::Value fields.
	void SendEntry(ReaderFrontend* reader, threading::Value* *vals);
	void EndCurrentSend(ReaderFrontend* reader);

	// Allows readers to directly send Bro events. The num_vals and vals
	// must be the same the named event expects. Takes ownership of
	// threading::Value fields.
	bool SendEvent(const string& name, const int num_vals, threading::Value* *vals);

	// Instantiates a new ReaderBackend of the given type (note that
	// doing so creates a new thread!).
	ReaderBackend* CreateBackend(ReaderFrontend* frontend, bro_int_t type);

	// Function called from the ReaderBackend to notify the manager that
	// a stream has been removed or a stream has been closed. Used to
	// prevent race conditions where data for a specific stream is still
	// in the queue when the RemoveStream directive is executed by the
	// main thread. This makes sure all data that has ben queued for a
	// stream is still received.
	bool RemoveStreamContinuation(ReaderFrontend* reader);

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

	// SendEntry implementation for Table stream.
	int SendEntryTable(Stream* i, const threading::Value* const *vals);

	// Put implementation for Table stream.
	int PutTable(Stream* i, const threading::Value* const *vals);

	// SendEntry and Put implementation for Event stream.
	int SendEventStreamEvent(Stream* i, EnumVal* type, const threading::Value* const *vals);

	// Checks that a Bro type can be used for data reading. The
	// equivalend in threading cannot be used, because we have support
	// different types from the log framework
	bool IsCompatibleType(BroType* t, bool atomic_only=false);
	// Check if a record is made up of compatible types and return a list
	// of all fields that are in the record in order. Recursively unrolls
	// records
	bool UnrollRecordType(vector<threading::Field*> *fields, const RecordType *rec, const string& nameprepend, bool allow_file_func);

	// Send events
	void SendEvent(EventHandlerPtr ev, const int numvals, ...);
	void SendEvent(EventHandlerPtr ev, list<Val*> events);

	// Implementation of SendEndOfData (send end_of_data event).
	void SendEndOfData(const Stream *i);

	// Call predicate function and return result.
	bool CallPred(Func* pred_func, const int numvals, ...);

	// Get a hashkey for a set of threading::Values.
	HashKey* HashValues(const int num_elements, const threading::Value* const *vals);

	// Get the memory used by a specific value.
	int GetValueLength(const threading::Value* val);

	// Copies the raw data in a specific threading::Value to position
	// startpos.
	int CopyValue(char *data, const int startpos, const threading::Value* val);

	// Convert Threading::Value to an internal Bro Type (works also with
	// Records).
	Val* ValueToVal(const threading::Value* val, BroType* request_type);

	// Convert Threading::Value to an internal Bro List type.
	Val* ValueToIndexVal(int num_fields, const RecordType* type, const threading::Value* const *vals);

	// Converts a threading::value to a record type. Mostly used by
	// ValueToVal.
	RecordVal* ValueToRecordVal(const threading::Value* const *vals, RecordType *request_type, int* position);

	Val* RecordValToIndexVal(RecordVal *r);

	// Converts a Bro ListVal to a RecordVal given the record type.
	RecordVal* ListValToRecordVal(ListVal* list, RecordType *request_type, int* position);

	Stream* FindStream(const string &name);
	Stream* FindStream(ReaderFrontend* reader);

	enum StreamType { TABLE_STREAM, EVENT_STREAM, ANALYSIS_STREAM };

	map<ReaderFrontend*, Stream*> readers;

	EventHandlerPtr end_of_data;
};


}

extern input::Manager* input_mgr;


#endif /* INPUT_MANAGER_H */
