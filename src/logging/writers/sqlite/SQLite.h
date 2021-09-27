// See the file "COPYING" in the main distribution directory for copyright.
//
// Log writer for SQLITE logs.

#pragma once

#include "zeek/zeek-config.h"

#include "zeek/3rdparty/sqlite3.h"
#include "zeek/Desc.h"
#include "zeek/logging/WriterBackend.h"
#include "zeek/threading/formatters/Ascii.h"

namespace zeek::logging::writer::detail
	{

class SQLite : public WriterBackend
	{
public:
	explicit SQLite(WriterFrontend* frontend);
	~SQLite() override;

	static WriterBackend* Instantiate(WriterFrontend* frontend) { return new SQLite(frontend); }

protected:
	bool DoInit(const WriterInfo& info, int arg_num_fields,
	            const threading::Field* const* arg_fields) override;
	bool DoWrite(int num_fields, const threading::Field* const* fields,
	             threading::Value** vals) override;
	bool DoSetBuf(bool enabled) override { return true; }
	bool DoRotate(const char* rotated_path, double open, double close, bool terminating) override;
	bool DoFlush(double network_time) override { return true; }
	bool DoFinish(double network_time) override { return true; }
	bool DoHeartbeat(double network_time, double current_time) override { return true; }

private:
	bool checkError(int code);

	int AddParams(threading::Value* val, int pos);
	std::string GetTableType(int, int);

	const threading::Field* const* fields; // raw mapping
	unsigned int num_fields;

	sqlite3* db;
	sqlite3_stmt* st;

	std::string set_separator;
	std::string unset_field;
	std::string empty_field;

	threading::formatter::Ascii* io;
	};

	} // namespace zeek::logging::writer::detail
