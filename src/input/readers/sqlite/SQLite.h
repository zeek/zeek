// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#include <iostream>
#include <vector>

#include "input/ReaderBackend.h"
#include "threading/formatters/Ascii.h"
#include "3rdparty/sqlite3.h"

namespace zeek::input::reader::detail {

class SQLite : public zeek::input::ReaderBackend {
public:
	explicit SQLite(zeek::input::ReaderFrontend* frontend);
	~SQLite() override;

	static zeek::input::ReaderBackend* Instantiate(zeek::input::ReaderFrontend* frontend) { return new SQLite(frontend); }

protected:
	bool DoInit(const ReaderInfo& info, int arg_num_fields, const zeek::threading::Field* const* arg_fields) override;
	void DoClose() override;
	bool DoUpdate() override;
	bool DoHeartbeat(double network_time, double current_time) override { return true; }

private:
	bool checkError(int code);

	zeek::threading::Value* EntryToVal(sqlite3_stmt *st, const zeek::threading::Field *field, int pos, int subpos);

	const threading::Field* const * fields; // raw mapping
	unsigned int num_fields;
	int mode;
	bool started;
	std::string query;
	sqlite3 *db;
	sqlite3_stmt *st;
	zeek::threading::formatter::Ascii* io;

	std::string set_separator;
	std::string unset_field;
	std::string empty_field;
};

} // namespace zeek::input::reader

namespace input::reader {
	using SQLite [[deprecated("Remove in v4.1. Use zeek::input::reader::detail::SQLite.")]] = zeek::input::reader::detail::SQLite;
}
