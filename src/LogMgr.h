// See the file "COPYING" in the main distribution directory for copyright.
//
// A class managing log writers and filters.

#ifndef LOGMGR_H
#define LOGMGR_H

#include "Val.h"
#include "EventHandler.h"
#include "RemoteSerializer.h"
#include "LogWriter.h"
#include "ThreadSafeQueue.h"

class SerializationFormat;

namespace bro
{
class LogEmissary;
}

using bro::LogEmissary;

// Description of a log field.
struct LogField {
	string name;
	TypeTag type;

	LogField()	{ }
	LogField(const LogField& other)
		: name(other.name), type(other.type)	{ }

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

namespace bro
{
class LogWriter;
class MessageEvent;
}

class RemoteSerializer;
class RotationTimer;

class LogWriterRegistrar {
public:
	typedef bro::LogWriter* (*InstantiateFunction)( const LogEmissary&, bro::QueueInterface<bro::MessageEvent *>&, bro::QueueInterface<bro::MessageEvent *>& );
	LogWriterRegistrar(const bro_int_t type, const char *name, 
							bool(*init)(), InstantiateFunction factory);
	LogWriterRegistrar(const bro_int_t type, const char *name, 
							InstantiateFunction factory);
};

class LogMgr {
public:
	LogMgr();
	~LogMgr();

	/**
	 *  Registers a new log writer so that scripts can use it.
	 *
	 *  This function modifies the shared log_writers object; it is therefore *not*
	 *  thread-safe.
	 *
	 *  @param type BifEnum::Log::WRITER_NAME
	 *  @param name Common name of this writer (e.g. "ASCII") 
	 *  @param init Function to call (once!) before *any* instances are built
	 *  @param factory Function used to instantiate this type of LogWriter (probably MyLogClass::Instantiate) 
	*/
	static void RegisterWriter(const bro_int_t type, const char *name,
								  bool (*init)(), LogWriterRegistrar::InstantiateFunction factory);

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
	friend class LogEmissary;
	friend class RemoteSerializer;
	friend class RotationTimer;

	//// Function also used by the RemoteSerializer.

	// Takes ownership of fields.
	LogEmissary* CreateWriter(EnumVal* id, EnumVal* writer, string path,
				int num_fields, LogField** fields);

	// Takes ownership of values..
	bool Write(EnumVal* id, EnumVal* writer, string path,
		   int num_fields, LogVal** vals);

	// Announces all instantiated writers to peer.
	void SendAllWritersTo(RemoteSerializer::PeerID peer);

	//// Functions safe to use by writers.

	// Reports an error for the given writer.
	void Error(LogEmissary* writer, const char* msg);

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
	RecordVal* LookupRotationControl(EnumVal* writer, string path);
	Filter* FindFilter(EnumVal* id, StringVal* filter);

	vector<Stream *> streams;	// Indexed by stream enum.
};

extern LogMgr* log_mgr;

#endif
