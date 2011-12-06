// See the file "COPYING" in the main distribution directory for copyright.
//
// A class managing log writers and filters.

#ifndef LOGMGR_H
#define LOGMGR_H

#include "Val.h"
#include "EventHandler.h"
#include "RemoteSerializer.h"

class SerializationFormat;

// Description of a log field.
struct LogField {
	string name;
	// needed by input framework. port fields have two names (one for the port, one for the type) - this specifies the secondary name.
	string secondary_name;
	TypeTag type;
	// needed by input framework. otherwise it cannot determine the inner type of a set.
	TypeTag subtype;

	LogField()	{ }
	LogField(const LogField& other)
		: name(other.name), secondary_name(other.secondary_name), type(other.type), subtype(other.subtype) { }

	// (Un-)serialize.
	bool Read(SerializationFormat* fmt);
	bool Write(SerializationFormat* fmt) const;
};

// Values as logged by a writer.
struct LogVal {
	TypeTag type;
	bool present; // False for unset fields.

	// The following union is a subset of BroValUnion, including only the
	// types we can log directly.
	struct set_t { bro_int_t size; LogVal** vals; };
	typedef set_t vec_t;
	struct port_t { bro_uint_t port; string* proto; };

	union _val {
		bro_int_t int_val;
		bro_uint_t uint_val;
		port_t port_val;
		uint32 addr_val[NUM_ADDR_WORDS];
		subnet_type subnet_val;
		double double_val;
		string* string_val;
		set_t set_val;
		vec_t vector_val;
	} val;

	LogVal(TypeTag arg_type = TYPE_ERROR, bool arg_present = true)
		: type(arg_type), present(arg_present)	{}
	~LogVal();

	// (Un-)serialize.
	bool Read(SerializationFormat* fmt);
	bool Write(SerializationFormat* fmt) const;

	// Returns true if the type can be logged the framework. If
	// `atomic_only` is true, will not permit composite types.
	static bool IsCompatibleType(BroType* t, bool atomic_only=false);

private:
	LogVal(const LogVal& other)	{ }
};

class LogWriter;
class RemoteSerializer;
class RotationTimer;

class LogMgr {
public:
	LogMgr();
	~LogMgr();

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
	friend class LogWriter;
	friend class RemoteSerializer;
	friend class RotationTimer;

	//// Function also used by the RemoteSerializer.

	// Takes ownership of fields.
	LogWriter* CreateWriter(EnumVal* id, EnumVal* writer, string path,
				int num_fields, LogField** fields);

	// Takes ownership of values..
	bool Write(EnumVal* id, EnumVal* writer, string path,
		   int num_fields, LogVal** vals);

	// Announces all instantiated writers to peer.
	void SendAllWritersTo(RemoteSerializer::PeerID peer);

	//// Functions safe to use by writers.

	// Signals that a file has been rotated.
	bool FinishedRotation(LogWriter* writer, string new_name, string old_name,
			      double open, double close, bool terminating);

	// Reports an error for the given writer.
	void Error(LogWriter* writer, const char* msg);

	// Deletes the values as passed into Write().
	void DeleteVals(int num_fields, LogVal** vals);

private:
	struct Filter;
	struct Stream;
	struct WriterInfo;

	bool TraverseRecord(Stream* stream, Filter* filter, RecordType* rt,
			    TableVal* include, TableVal* exclude, string path, list<int> indices);

	LogVal** RecordToFilterVals(Stream* stream, Filter* filter,
				    RecordVal* columns);

	LogVal* ValToLogVal(Val* val, BroType* ty = 0);
	Stream* FindStream(EnumVal* id);
	void RemoveDisabledWriters(Stream* stream);
	void InstallRotationTimer(WriterInfo* winfo);
	void Rotate(WriterInfo* info);
	Filter* FindFilter(EnumVal* id, StringVal* filter);
	WriterInfo* FindWriter(LogWriter* writer);

	string TransportProtoToString(TransportProto p);

	vector<Stream *> streams;	// Indexed by stream enum.
};

extern LogMgr* log_mgr;

#endif
