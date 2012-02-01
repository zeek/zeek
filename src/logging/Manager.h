// See the file "COPYING" in the main distribution directory for copyright.
//
// A class managing log writers and filters.

#ifndef LOGGING_MANAGER_H
#define LOGGING_MANAGER_H

#include "../Val.h"
#include "../EventHandler.h"
#include "../RemoteSerializer.h"

class SerializationFormat;
class RemoteSerializer;
class RotationTimer;

namespace logging {

/**
 * Definition of a log file, i.e., one column of a log stream.
 */
struct Field {
	string name;	//! Name of the field.
	TypeTag type;	//! Type of the field.
	TypeTag subtype;	//! Inner type for sets.

	/**
	 * Constructor.
	 */
	Field() 	{ subtype = TYPE_VOID; }

	/**
	 * Copy constructor.
	 */
	Field(const Field& other)
		: name(other.name), type(other.type), subtype(other.subtype) {  }

	/**
	 * Unserializes a field.
	 *
	 * @param fmt The serialization format to use. The format handles
	 * low-level I/O.
	 *
	 * @return False if an error occured.
	 */
	bool Read(SerializationFormat* fmt);

	/**
	 * Serializes a field.
	 *
	 * @param fmt The serialization format to use. The format handles
	 * low-level I/O.
	 *
	 * @return False if an error occured.
	 */
	bool Write(SerializationFormat* fmt) const;
};

/**
 * Definition of a log value, i.e., a entry logged by a stream.
 *
 * This struct essentialy represents a serialization of a Val instance (for
 * those Vals supported).
 */
struct Value {
	TypeTag type;	//! The type of the value.
	bool present;	//! False for optional record fields that are not set.

	struct set_t { bro_int_t size; Value** vals; };
	typedef set_t vec_t;

	/**
	 * This union is a subset of BroValUnion, including only the types we
	 * can log directly. See IsCompatibleType().
	 */
	union _val {
		bro_int_t int_val;
		bro_uint_t uint_val;
		uint32 addr_val[NUM_ADDR_WORDS];
		subnet_type subnet_val;
		double double_val;
		string* string_val;
		set_t set_val;
		vec_t vector_val;
	} val;

	/**
	* Constructor.
	*
	* arg_type: The type of the value.
	*
	* arg_present: False if the value represents an optional record field
	* that is not set.
	 */
	Value(TypeTag arg_type = TYPE_ERROR, bool arg_present = true)
		: type(arg_type), present(arg_present)	{}

	/**
	 * Destructor.
	 */
	~Value();

	/**
	 * Unserializes a value.
	 *
	 * @param fmt The serialization format to use. The format handles low-level I/O.
	 *
	 * @return False if an error occured.
	 */
	bool Read(SerializationFormat* fmt);

	/**
	 * Serializes a value.
	 *
	 * @param fmt The serialization format to use. The format handles
	 * low-level I/O.
	 *
	 * @return False if an error occured.
	 */
	bool Write(SerializationFormat* fmt) const;

	/**
	 * Returns true if the type can be represented by a Value. If
	 * `atomic_only` is true, will not permit composite types.
	 */
	static bool IsCompatibleType(BroType* t, bool atomic_only=false);

private:
	Value(const Value& other)	{ } // Disabled.
};

class WriterBackend;
class WriterFrontend;
class RotationFinishedMessage;

/**
 * Singleton class for managing log streams.
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
	 * Creates a new log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param stream A record of script type \c Log::Stream.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool CreateStream(EnumVal* id, RecordVal* stream);

	/**
	 * Enables a log log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool EnableStream(EnumVal* id);

	/**
	 * Disables a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool DisableStream(EnumVal* id);

	/**
	 * Adds a filter to a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param filter A record of script type \c Log::Filter.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool AddFilter(EnumVal* id, RecordVal* filter);

	/**
	 * Removes a filter from a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param name The name of the filter to remove.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool RemoveFilter(EnumVal* id, StringVal* name);

	/**
	 * Removes a filter from a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param name The name of the filter to remove.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool RemoveFilter(EnumVal* id, string name);

	/**
	 * Write a record to a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param colums A record of the type defined for the stream's
	 * columns.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool Write(EnumVal* id, RecordVal* columns);

	/**
	 * Sets log streams buffering state. This adjusts all associated
	 * writers to the new state.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param enabled False to disable buffering (default is enabled).
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool SetBuf(EnumVal* id, bool enabled);

	/**
	 * Flushes a log stream. This flushed all associated writers.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool Flush(EnumVal* id);

protected:
	friend class WriterFrontend;
	friend class RotationFinishedMessage;
	friend class ::RemoteSerializer;
	friend class ::RotationTimer;

	// Instantiates a new WriterBackend of the given type (note that
	// doing so creates a new thread!). 
	WriterBackend* CreateBackend(bro_int_t type);

	//// Function also used by the RemoteSerializer.

	// Takes ownership of fields.
	WriterFrontend* CreateWriter(EnumVal* id, EnumVal* writer, string path,
				int num_fields, const Field* const*  fields);

	// Takes ownership of values..
	bool Write(EnumVal* id, EnumVal* writer, string path,
		   int num_fields, Value** vals);

	// Announces all instantiated writers to peer.
	void SendAllWritersTo(RemoteSerializer::PeerID peer);

	// Signals that a file has been rotated.
	bool FinishedRotation(WriterFrontend* writer, string new_name, string old_name,
			      double open, double close, bool terminating);

	// Reports an error for the given writer.
	void Error(WriterFrontend* writer, const char* msg);

	// Deletes the values as passed into Write().
	void DeleteVals(int num_fields, Value** vals);

private:
	struct Filter;
	struct Stream;
	struct WriterInfo;

	bool TraverseRecord(Stream* stream, Filter* filter, RecordType* rt,
			    TableVal* include, TableVal* exclude, string path, list<int> indices);

	Value** RecordToFilterVals(Stream* stream, Filter* filter,
				    RecordVal* columns);

	Value* ValToLogVal(Val* val, BroType* ty = 0);
	Stream* FindStream(EnumVal* id);
	void RemoveDisabledWriters(Stream* stream);
	void InstallRotationTimer(WriterInfo* winfo);
	void Rotate(WriterInfo* info);
	Filter* FindFilter(EnumVal* id, StringVal* filter);
	WriterInfo* FindWriter(WriterFrontend* writer);

	vector<Stream *> streams;	// Indexed by stream enum.
};

}

extern logging::Manager* log_mgr;

#endif
