// See the file "COPYING" in the main distribution directory for copyright.
//
// A class managing log writers and filters.

#ifndef LOGMGR_H
#define LOGMGR_H

#include "Val.h"
#include "LogBase.h"
#include "LogWriter.h"
#include "RemoteSerializer.h"

class SerializationFormat;
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
	void Shutdown();

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
