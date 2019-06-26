// See the file "COPYING" in the main distribution directory for copyright.
//
// Log writer for SQLITE logs.

#ifndef LOGGING_WRITER_SQLITE_H
#define LOGGING_WRITER_SQLITE_H

#include "zeek-config.h"

#include "logging/WriterBackend.h"
#include "threading/formatters/Ascii.h"
#include "3rdparty/sqlite3.h"

namespace logging { namespace writer {

class SQLite : public WriterBackend {
public:
	explicit SQLite(WriterFrontend* frontend);
	~SQLite() override;

	static WriterBackend* Instantiate(WriterFrontend* frontend)
		{ return new SQLite(frontend); }

protected:
	bool DoInit(const WriterInfo& info, int arg_num_fields,
			    const threading::Field* const* arg_fields) override;
	bool DoWrite(int num_fields, const threading::Field* const* fields,
			     threading::Value** vals) override;
	bool DoSetBuf(bool enabled) override { return true; }
	bool DoRotate(const char* rotated_path, double open,
			      double close, bool terminating) override;
	bool DoFlush(double network_time) override { return true; }
	bool DoFinish(double network_time) override { return true; }
	bool DoHeartbeat(double network_time, double current_time) override { return true; }

private:
	bool checkError(int code);

	int AddParams(threading::Value* val, int pos);
	string GetTableType(int, int);

	const threading::Field* const * fields; // raw mapping
	unsigned int num_fields;

	sqlite3 *db;
	sqlite3_stmt *st;

	string set_separator;
	string unset_field;
	string empty_field;

	threading::formatter::Ascii* io;
};

}
}

#endif /* LOGGING_WRITER_SQLITE_H */

