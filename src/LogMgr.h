//
// A class managing log writers and filters.

#ifndef LOGMGR_H
#define LOGMGR_H

#include "Val.h"
#include "EventHandler.h"

// One value per writer type we have.
namespace LogWriterType {
	enum Type {
		None,
		Ascii
	};
};

struct LogField {
	LogField()	{ }
	LogField(const LogField& other) : name(other.name), type(other.type)	{ }
	string name;
	TypeTag type;
};

// A string that we can directly include as part of the value union below.
struct log_string_type {
	int len;
	char string[]; // The string starts right here.
};

// All values that can be directly logged by a Writer.
struct LogVal {
	LogVal(bool arg_present = true) : present(arg_present)	{}

	bool present; // If false, the field is unset (i.e., &optional and not initialzed).

	// The following union is a subset of BroValUnion, including only the
	// atomic types.
 	union {
		bro_int_t int_val;
		bro_uint_t uint_val;
		addr_type addr_val;
		subnet_type subnet_val;
    	double double_val;
		log_string_type string_val;
	} val;
};

class LogWriter;

class LogMgr {
public:
    LogMgr();
    ~LogMgr();

    // These correspond to the BiFs visible on the scripting layer. The
    // actual BiFs just forward here.
    bool CreateStream(EnumVal* stream_id, RecordType* columns, EventHandlerPtr handler);
    bool AddFilter(EnumVal* stream_id, RecordVal* filter);
    bool RemoveFilter(EnumVal* stream_id, StringVal* filter);
    bool Write(EnumVal* stream_id, RecordVal* columns);
	bool SetBuf(EnumVal* stream_id, bool enabled); // Changes the state for all writers for that stream.

protected:
    friend class LogWriter;

	/// Functions also used by the writers.

    // Reports an error for the given writer.
    void Error(LogWriter* writer, const char* msg);

private:
	struct Filter;
	struct Stream;

	bool TraverseRecord(Filter* filter, RecordType* rt, TableVal* include, TableVal* exclude, string path, list<int> indices);
	LogVal** RecordToFilterVals(Filter* filter, RecordVal* columns);
	Stream* FindStream(EnumVal* stream_id);

	vector<Stream *> streams; // Indexed by stream enum.
};

extern LogMgr* log_mgr;

#endif
