// See the file "COPYING" in the main distribution directory for copyright.
//
// Class for managing input streams and filters

#ifndef INPUT_MANAGER_H
#define INPUT_MANAGER_H

#include "../BroString.h"

#include "../Val.h"
#include "../EventHandler.h"
#include "../RemoteSerializer.h"

#include <vector>

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
	 * Creates a new input stream.
	 *
	 * @param id  The enum value corresponding the input stream.
	 *
	 * @param description A record of script type \c Input:StreamDescription.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * input.bif, which just forwards here.
	 */	
    	ReaderFrontend* CreateStream(EnumVal* id, RecordVal* description);

	/**
	 * Force update on a input stream.
	 * Forces a re-read of the whole input source.
	 * Usually used, when an input stream is opened in managed mode.
	 * Otherwise, this can be used to trigger a input source check before a heartbeat message arrives.
	 * May be ignored by the reader.
	 *
	 * @param id  The enum value corresponding the input stream.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * input.bif, which just forwards here.
	 */
	bool ForceUpdate(const EnumVal* id);
	
	/**
	 * Deletes an existing input stream
	 *
	 * @param id  The enum value corresponding the input stream.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * input.bif, which just forwards here.
	 */
	bool RemoveStream(const EnumVal* id);	

	/** 
	 * Add a filter to an input source, which will write the data from the data source into 
	 * a Bro table.
	 *
	 * @param id  The enum value corresponding the input stream.
	 * 
	 * @param description A record of script type \c Input:TableFilter.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * input.bif, which just forwards here.
	 */
	bool AddTableFilter(EnumVal *id, RecordVal* filter);

	/**
	 * Removes a tablefilter from the log stream
	 *
	 * @param id  The enum value corresponding the input stream.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * input.bif, which just forwards here.
	 */
	bool RemoveTableFilter(EnumVal* id, const string &name);

	/** 
	 * Add a filter to an input source, which sends events for read input data.
	 *
	 * @param id  The enum value corresponding the input stream.
	 * 
	 * @param description A record of script type \c Input:EventFilter.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * input.bif, which just forwards here.
	 */
	bool AddEventFilter(EnumVal *id, RecordVal* filter);

	/**
	 * Removes a eventfilter from the log stream
	 *
	 * @param id  The enum value corresponding the input stream.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * input.bif, which just forwards here.
	 */
	bool RemoveEventFilter(EnumVal* id, const string &name);
	
protected:
	friend class ReaderFrontend;
	friend class PutMessage;
	friend class DeleteMessage;
	friend class ClearMessage;
	friend class SendEventMessage;
	friend class SendEntryMessage;
	friend class EndCurrentSendMessage;
	friend class FilterRemovedMessage;
	friend class ReaderFinishedMessage;

	// For readers to write to input stream in direct mode (reporting new/deleted values directly)
	// Functions take ownership of threading::Value fields
	void Put(const ReaderFrontend* reader, int id, threading::Value* *vals);
	void Clear(const ReaderFrontend* reader, int id);
	bool Delete(const ReaderFrontend* reader, int id, threading::Value* *vals);

	// for readers to write to input stream in indirect mode (manager is monitoring new/deleted values)
	// Functions take ownership of threading::Value fields
	void SendEntry(const ReaderFrontend* reader, const int id, threading::Value* *vals);
	void EndCurrentSend(const ReaderFrontend* reader, const int id);
	
	// Allows readers to directly send Bro events.
	// The num_vals and vals must be the same the named event expects.
	// Takes ownership of threading::Value fields
	bool SendEvent(const string& name, const int num_vals, threading::Value* *vals);

	// Instantiates a new ReaderBackend of the given type (note that
	// doing so creates a new thread!).	
	ReaderBackend* CreateBackend(ReaderFrontend* frontend, bro_int_t type);	
	
	// Functions are called from the ReaderBackend to notify the manager, that a filter has been removed
	// or a stream has been closed.
	// Used to prevent race conditions where data for a specific filter is still in the queue when the 
	// RemoveFilter directive is executed by the main thread.
	// This makes sure all data that has ben queued for a filter is still received.
	bool RemoveFilterContinuation(const ReaderFrontend* reader, const int filterId);
	bool RemoveStreamContinuation(const ReaderFrontend* reader);
	
private:
	struct ReaderInfo;

	// SendEntry implementation for Tablefilter
	int SendEntryTable(const ReaderFrontend* reader, int id, const threading::Value* const *vals);	

	// Put implementation for Tablefilter
	int PutTable(const ReaderFrontend* reader, int id, const threading::Value* const *vals);	

	// SendEntry and Put implementation for Eventfilter
	int SendEventFilterEvent(const ReaderFrontend* reader, EnumVal* type, int id, const threading::Value* const *vals);

	// Checks is a bro type can be used for data reading. The equivalend in threading cannot be used, because we have support different types 
	// from the log framework
	bool IsCompatibleType(BroType* t, bool atomic_only=false);

	// Check if a record is made up of compatible types and return a list of all fields that are in the record in order.
	// Recursively unrolls records
	bool UnrollRecordType(vector<threading::Field*> *fields, const RecordType *rec, const string& nameprepend);

	// Send events
	void SendEvent(EventHandlerPtr ev, const int numvals, ...);	
	void SendEvent(EventHandlerPtr ev, list<Val*> events);	

	// get a hashkey for a set of threading::Values
	HashKey* HashValues(const int num_elements, const threading::Value* const *vals);

	// Get the memory used by a specific value
	int GetValueLength(const threading::Value* val);
	// Copies the raw data in a specific threading::Value to position sta
	int CopyValue(char *data, const int startpos, const threading::Value* val);

	// Convert Threading::Value to an internal Bro Type (works also with Records)
	Val* ValueToVal(const threading::Value* val, BroType* request_type);

	// Convert Threading::Value to an internal Bro List type
	Val* ValueToIndexVal(int num_fields, const RecordType* type, const threading::Value* const *vals);

	// Converts a threading::value to a record type. mostly used by ValueToVal
	RecordVal* ValueToRecordVal(const threading::Value* const *vals, RecordType *request_type, int* position);	
	
	// Converts a Bro ListVal to a RecordVal given the record type
	RecordVal* ListValToRecordVal(ListVal* list, RecordType *request_type, int* position);

	ReaderInfo* FindReader(const ReaderFrontend* reader);
	ReaderInfo* FindReader(const EnumVal* id);

	vector<ReaderInfo*> readers;

	class Filter;
	class TableFilter;
	class EventFilter;

	enum FilterType { TABLE_FILTER, EVENT_FILTER };
};


}

extern input::Manager* input_mgr;


#endif /* INPUT_MANAGER_H */
