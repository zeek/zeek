// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERS_POSTGRES_H
#define INPUT_READERS_POSTGRES_H

#include "config.h"

#include <iostream>
#include <vector>

#include "../ReaderBackend.h"

#include "threading/formatters/Ascii.h"
#include "3rdparty/sqlite3.h"

namespace input { namespace reader {

class SQLite : public ReaderBackend {
public:
	SQLite(ReaderFrontend* frontend);
	~SQLite();

	static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new SQLite(frontend); }

protected:
	virtual bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* arg_fields);
	virtual void DoClose();
	virtual bool DoUpdate();
	virtual bool DoHeartbeat(double network_time, double current_time)	{ return true; }

private:
	bool checkError(int code);

	threading::Value* EntryToVal(sqlite3_stmt *st, const threading::Field *field, int pos, int subpos);

	const threading::Field* const * fields; // raw mapping
	unsigned int num_fields;
	int mode;
	bool started;
	string query;
	sqlite3 *db;
	sqlite3_stmt *st;
	threading::formatter::Ascii* io;

	string set_separator;
	string unset_field;
	string empty_field;
};


}
}

#endif /* INPUT_READERS_POSTGRES_H */

