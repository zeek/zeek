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

// Description of a log field.
struct Field {
	string name;
	TypeTag type;
	// inner type of sets
	TypeTag subtype;

	Field() 	{ subtype = TYPE_VOID; }
	Field(const Field& other)
		: name(other.name), type(other.type), subtype(other.subtype) {  }

	// (Un-)serialize.
	bool Read(SerializationFormat* fmt);
	bool Write(SerializationFormat* fmt) const;
};

// Values as logged by a writer.
struct Value {
	TypeTag type;
	bool present; // False for unset fields.

	// The following union is a subset of BroValUnion, including only the
	// types we can log directly.
	struct set_t { bro_int_t size; Value** vals; };
	typedef set_t vec_t;

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

	Value(TypeTag arg_type = TYPE_ERROR, bool arg_present = true)
		: type(arg_type), present(arg_present)	{}
	~Value();

	// (Un-)serialize.
	bool Read(SerializationFormat* fmt);
	bool Write(SerializationFormat* fmt) const;

	// Returns true if the type can be logged the framework. If
	// `atomic_only` is true, will not permit composite types.
	static bool IsCompatibleType(BroType* t, bool atomic_only=false);

private:
	Value(const Value& other)	{ }
};

class WriterBackend;
class WriterFrontend;
class RotationFinishedMessage;

class Manager {
public:
	Manager();
	~Manager();

	// These correspond to the BiFs visible on the scripting layer. The
	// actual BiFs just forward here.
	bool CreateStream(EnumVal* id, RecordVal* stream);
	bool EnableStream(EnumVal* id);
	bool DisableStream(EnumVal* id);
	bool AddFilter(EnumVal* id, RecordVal* filter);
	bool RemoveFilter(EnumVal* id, StringVal* name);
	bool RemoveFilter(EnumVal* id, string name);
	bool Write(EnumVal* id, RecordVal* columns);
	bool SetBuf(EnumVal* id, bool enabled);	// Adjusts all writers.
	bool Flush(EnumVal* id);		// Flushes all writers..

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
				int num_fields, Field** fields);

	// Takes ownership of values..
	bool Write(EnumVal* id, EnumVal* writer, string path,
		   int num_fields, Value** vals);

	// Announces all instantiated writers to peer.
	void SendAllWritersTo(RemoteSerializer::PeerID peer);

	//// Functions safe to use by writers.

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
