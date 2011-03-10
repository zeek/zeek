//
// A class managing log writers and filters.

#ifndef LOGMGR_H
#define LOGMGR_H

#include "Val.h"
#include "EventHandler.h"
#include "RemoteSerializer.h"

class SerializationFormat;

struct LogField {
	string name;
	TypeTag type;

	LogField()	{ }
	LogField(const LogField& other) : name(other.name), type(other.type)	{ }

	bool Read(SerializationFormat* fmt)
		{
		int t;
		bool success = fmt->Read(&name, "name") && fmt->Read(&t, "type");
		type = (TypeTag) t;
		return success;
		}

	bool Write(SerializationFormat* fmt) const
		{ return fmt->Write(name, "name") && fmt->Write((int)type, "type"); }
};

// All values that can be directly logged by a Writer.
struct LogVal {
	TypeTag type;
	bool present; // If false, the field is unset (i.e., &optional and not initialzed).

	// The following union is a subset of BroValUnion, including only the
	// atomic types.
	struct set_t { bro_int_t size; LogVal** vals; };

 	union _val {
		bro_int_t int_val;
		bro_uint_t uint_val;
		addr_type addr_val;
		subnet_type subnet_val;
    	double double_val;
		string* string_val;
		set_t set_val;
	} val;

	LogVal(TypeTag arg_type = TYPE_ERROR, bool arg_present = true) : type(arg_type), present(arg_present)	{}
	~LogVal();

	bool Read(SerializationFormat* fmt);
	bool Write(SerializationFormat* fmt) const;

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
	bool SetBuf(EnumVal* id, bool enabled); // Changes the state for all writers for that stream.
	bool Flush(EnumVal* id); // Flushes all writers for the stream.

protected:
    friend class LogWriter;
	friend class RemoteSerializer;
	friend class RotationTimer;

	// These function are also used by the RemoteSerializer.
	LogWriter* CreateWriter(EnumVal* id, EnumVal* writer, string path, int num_fields, LogField** fields); // takes ownership of fields.
	bool Write(EnumVal* id, EnumVal* writer, string path, int num_fields, LogVal** vals); // takes ownership of vals.
	void SendAllWritersTo(RemoteSerializer::PeerID peer);

	/// Functions also used by the writers.

    // Reports an error for the given writer.
    void Error(LogWriter* writer, const char* msg);

private:
	struct Filter;
	struct Stream;
	struct WriterInfo;

	bool TraverseRecord(Filter* filter, RecordType* rt, TableVal* include, TableVal* exclude, string path, list<int> indices);
	LogVal* ValToLogVal(Val* val);
	LogVal** RecordToFilterVals(Filter* filter, RecordVal* columns);
	Stream* FindStream(EnumVal* id);
	void RemoveDisabledWriters(Stream* stream);
	void InstallRotationTimer(WriterInfo* winfo);
	void Rotate(WriterInfo* info);
	RecordVal* LookupRotationControl(EnumVal* writer, string path);
	Filter* FindFilter(EnumVal* id, StringVal* filter);

	vector<Stream *> streams; // Indexed by stream enum.
};

extern LogMgr* log_mgr;

#endif
