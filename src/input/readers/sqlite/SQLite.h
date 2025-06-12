// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>

#include "zeek/3rdparty/sqlite3.h"
#include "zeek/input/ReaderBackend.h"
#include "zeek/threading/formatters/Ascii.h"

namespace zeek::input::reader::detail {

class SQLite : public ReaderBackend {
public:
    explicit SQLite(ReaderFrontend* frontend);
    ~SQLite() override;

    static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new SQLite(frontend); }

protected:
    bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* arg_fields) override;
    void DoClose() override;
    bool DoUpdate() override;
    bool DoHeartbeat(double network_time, double current_time) override { return true; }

private:
    bool checkError(int code);

    threading::Value* EntryToVal(sqlite3_stmt* st, const threading::Field* field, int pos, int subpos);

    const threading::Field* const* fields = nullptr; // raw mapping
    unsigned int num_fields = 0;
    int mode = 0;
    bool started = false;
    std::string query;
    sqlite3* db = nullptr;
    sqlite3_stmt* st = nullptr;
    threading::formatter::Ascii* io = nullptr;

    std::string set_separator;
    std::string unset_field;
    std::string empty_field;
};

} // namespace zeek::input::reader::detail
