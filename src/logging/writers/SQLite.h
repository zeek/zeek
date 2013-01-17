// See the file "COPYING" in the main distribution directory for copyright.
//
// Log writer for SQLITE logs.


#ifndef LOGGING_WRITER_SQLITE_H
#define LOGGING_WRITER_SQLITE_H

#include "config.h"

#ifdef USE_SQLITE

#include "../WriterBackend.h"
#include "sqlite3.h"
#include "../../threading/AsciiInputOutput.h"

namespace logging { namespace writer {

class SQLite : public WriterBackend {
public:
	SQLite(WriterFrontend* frontend);
	~SQLite();

	static WriterBackend* Instantiate(WriterFrontend* frontend)
		{ return new SQLite(frontend); }

protected:
	virtual bool DoInit(const WriterInfo& info, int num_fields,
			    const threading::Field* const* fields);
	virtual bool DoWrite(int num_fields, const threading::Field* const* fields,
			     threading::Value** vals);
	virtual bool DoSetBuf(bool enabled) { return true; }
	virtual bool DoRotate(const char* rotated_path, double open,
			      double close, bool terminating) { return true; }
	virtual bool DoFlush(double network_time)	{ return true; }
	virtual bool DoFinish(double network_time)	{ return true; }
	virtual bool DoHeartbeat(double network_time, double current_time)	{ return true; }

private:
	bool checkError(int code);

	int AddParams(threading::Value* val, int pos);
	string GetTableType(int, int);
	char* FS(const char* format, ...);

	sqlite3 *db;
	sqlite3_stmt *st;

	string set_separator;
	string unset_field;
	string empty_field;	
	
	AsciiInputOutput* io;
};

}
}

#endif /* USE_SQLITE */

#endif /* LOGGING_WRITER_SQLITE_H */

