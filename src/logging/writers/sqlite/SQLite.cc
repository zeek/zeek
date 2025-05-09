// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/logging/writers/sqlite/SQLite.h"

#include <cerrno>
#include <string>

#include "zeek/Desc.h"
#include "zeek/logging/writers/sqlite/sqlite.bif.h"
#include "zeek/threading/SerialTypes.h"
#include "zeek/util.h"

using namespace std;
using zeek::threading::Field;
using zeek::threading::Value;

namespace zeek::logging::writer::detail {

SQLite::SQLite(WriterFrontend* frontend) : WriterBackend(frontend), fields(), num_fields(), db(), st() {
    set_separator.assign((const char*)BifConst::LogSQLite::set_separator->Bytes(),
                         BifConst::LogSQLite::set_separator->Len());

    unset_field.assign((const char*)BifConst::LogSQLite::unset_field->Bytes(), BifConst::LogSQLite::unset_field->Len());

    empty_field.assign((const char*)BifConst::LogSQLite::empty_field->Bytes(), BifConst::LogSQLite::empty_field->Len());

    synchronous = BifConst::LogSQLite::synchronous->AsInt();
    journal_mode = BifConst::LogSQLite::journal_mode->AsInt();

    threading::formatter::Ascii::SeparatorInfo sep_info(string(), set_separator, unset_field, empty_field);
    io = new threading::formatter::Ascii(this, sep_info);
}

SQLite::~SQLite() {
    if ( db != 0 ) {
        sqlite3_finalize(st);
        if ( ! sqlite3_close(db) )
            Error("Sqlite could not close connection");

        db = 0;
    }

    delete io;
}

string SQLite::GetTableType(int arg_type, int arg_subtype) {
    string type;

    switch ( arg_type ) {
        case TYPE_BOOL: type = "boolean"; break;

        case TYPE_INT:
        case TYPE_COUNT:
        case TYPE_PORT: // note that we do not save the protocol at the moment. Just like in the
                        // case of the ascii-writer
            type = "integer";
            break;

        case TYPE_SUBNET:
        case TYPE_ADDR:
            type = "text"; // sqlite3 does not have a type for internet addresses
            break;

        case TYPE_TIME:
        case TYPE_INTERVAL:
        case TYPE_DOUBLE: type = "double precision"; break;

        case TYPE_ENUM:
        case TYPE_STRING:
        case TYPE_FILE:
        case TYPE_FUNC:
        case TYPE_TABLE:
        case TYPE_VECTOR:
            // For TYPE_TABLE and TYPE_VECTOR, this is sort of dirty, but sqlite does not
            // directly support arrays. so we just roll it all into a comma-separated string.
            type = "text";
            break;

        default:
            Error(Fmt("unsupported field format %d ", arg_type));
            return ""; // not the cleanest way to abort. But sqlite will complain on create table...
    }

    return type;
}

// returns true in case of error
bool SQLite::checkError(int code) {
    if ( code != SQLITE_OK && code != SQLITE_DONE ) {
        Error(Fmt("SQLite call failed: %s", sqlite3_errmsg(db)));
        return true;
    }

    return false;
}

bool SQLite::DoInit(const WriterInfo& info, int arg_num_fields, const Field* const* arg_fields) {
    if ( sqlite3_threadsafe() == 0 ) {
        Error(
            "SQLite reports that it is not threadsafe. Zeek needs a threadsafe version of "
            "SQLite. Aborting");
        return false;
    }

    // Allow connections to same DB to use single data/schema cache. Also
    // allows simultaneous writes to one file.
#ifndef ZEEK_TSAN
    sqlite3_enable_shared_cache(1);
#endif

    num_fields = arg_num_fields;
    fields = arg_fields;

    auto fullpath = zeek::filesystem::path(zeek::id::find_const<StringVal>("Log::default_logdir")->ToStdString());

    fullpath /= info.path;
    fullpath += ".sqlite";
    string tablename;

    WriterInfo::config_map::const_iterator it = info.config.find("tablename");
    if ( it == info.config.end() ) {
        MsgThread::Info(Fmt("tablename configuration option not found. Defaulting to path %s", info.path));
        tablename = info.path;
    }
    else
        tablename = it->second;

    if ( checkError(sqlite3_open_v2(fullpath.string().c_str(), &db,
                                    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, NULL)) )
        return false;

    char* errorMsg = nullptr;
    int res;
    switch ( synchronous ) {
        case BifEnum::LogSQLite::SQLiteSynchronous::SQLITE_SYNCHRONOUS_DEFAULT: res = SQLITE_OK; break;
        case BifEnum::LogSQLite::SQLiteSynchronous::SQLITE_SYNCHRONOUS_OFF:
            res = sqlite3_exec(db, "PRAGMA synchronous=OFF;", NULL, NULL, &errorMsg);
            break;
        case BifEnum::LogSQLite::SQLiteSynchronous::SQLITE_SYNCHRONOUS_NORMAL:
            res = sqlite3_exec(db, "PRAGMA synchronous=NORMAL;", NULL, NULL, &errorMsg);
            break;
        case BifEnum::LogSQLite::SQLiteSynchronous::SQLITE_SYNCHRONOUS_FULL:
            res = sqlite3_exec(db, "PRAGMA synchronous=FULL;", NULL, NULL, &errorMsg);
            break;
        case BifEnum::LogSQLite::SQLiteSynchronous::SQLITE_SYNCHRONOUS_EXTRA:
            res = sqlite3_exec(db, "PRAGMA synchronous=EXTRA;", NULL, NULL, &errorMsg);
            break;
        default: Error("Invalid LogSQLite::synchronous enum"); return false;
    }

    if ( res != SQLITE_OK ) {
        Error(Fmt("Error setting synchronous pragma: %s", errorMsg));
        sqlite3_free(errorMsg);
        return false;
    }

    switch ( journal_mode ) {
        case BifEnum::LogSQLite::SQLiteJournalMode::SQLITE_JOURNAL_MODE_DEFAULT: res = SQLITE_OK; break;
        case BifEnum::LogSQLite::SQLiteJournalMode::SQLITE_JOURNAL_MODE_DELETE:
            res = sqlite3_exec(db, "PRAGMA journal_mode=DELETE;", NULL, NULL, &errorMsg);
            break;
        case BifEnum::LogSQLite::SQLiteJournalMode::SQLITE_JOURNAL_MODE_TRUNCATE:
            res = sqlite3_exec(db, "PRAGMA journal_mode=TRUNCATE;", NULL, NULL, &errorMsg);
            break;
        case BifEnum::LogSQLite::SQLiteJournalMode::SQLITE_JOURNAL_MODE_PERSIST:
            res = sqlite3_exec(db, "PRAGMA journal_mode=PERSIST;", NULL, NULL, &errorMsg);
            break;
        case BifEnum::LogSQLite::SQLiteJournalMode::SQLITE_JOURNAL_MODE_MEMORY:
            res = sqlite3_exec(db, "PRAGMA journal_mode=MEMORY;", NULL, NULL, &errorMsg);
            break;
        case BifEnum::LogSQLite::SQLiteJournalMode::SQLITE_JOURNAL_MODE_WAL:
            res = sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, &errorMsg);
            break;
        case BifEnum::LogSQLite::SQLiteJournalMode::SQLITE_JOURNAL_MODE_OFF:
            res = sqlite3_exec(db, "PRAGMA journal_mode=OFF;", NULL, NULL, &errorMsg);
            break;
        default: Error("Invalid LogSQLite::journal_mode enum"); return false;
    }

    if ( res != SQLITE_OK ) {
        Error(Fmt("Error setting journal_mode pragma: %s", errorMsg));
        sqlite3_free(errorMsg);
        return false;
    }

    string create = "CREATE TABLE IF NOT EXISTS " + tablename + " (\n";
    //"id SERIAL UNIQUE NOT NULL"; // SQLite has rowids, we do not need a counter here.

    for ( unsigned int i = 0; i < num_fields; ++i ) {
        const Field* field = fields[i];

        if ( i != 0 )
            create += ",\n";

        // sadly sqlite3 has no other method for escaping stuff. That I know of.
        char* fieldname = sqlite3_mprintf("%Q", fields[i]->name);
        if ( fieldname == 0 ) {
            InternalError("Could not malloc memory");
            return false;
        }

        create += fieldname;

        string type = GetTableType(field->type, field->subtype);
        if ( type == "" ) {
            InternalError(Fmt("Could not determine type for field %u:%s", i, fieldname));
            sqlite3_free(fieldname);
            return false;
        }

        sqlite3_free(fieldname);
        create += " " + type;

        /* if ( !field->optional ) {
         create += " NOT NULL";
         } */
    }

    create += "\n);";

    errorMsg = nullptr;
    res = sqlite3_exec(db, create.c_str(), NULL, NULL, &errorMsg);
    if ( res != SQLITE_OK ) {
        Error(Fmt("Error executing table creation statement: %s", errorMsg));
        sqlite3_free(errorMsg);
        return false;
    }

    // create the prepared statement that will be re-used forever...
    string insert = "VALUES (";
    string names = "INSERT INTO " + tablename + " ( ";

    for ( unsigned int i = 0; i < num_fields; i++ ) {
        bool ac = true;

        if ( i == 0 )
            ac = false;
        else {
            names += ", ";
            insert += ", ";
        }

        insert += "?";

        char* fieldname = sqlite3_mprintf("%Q", fields[i]->name);
        if ( fieldname == 0 ) {
            InternalError("Could not malloc memory");
            return false;
        }

        names.append(fieldname);
        sqlite3_free(fieldname);
    }

    insert += ");";
    names += ") ";

    insert = names + insert;

    if ( checkError(sqlite3_prepare_v2(db, insert.c_str(), insert.size() + 1, &st, NULL)) )
        return false;

    return true;
}

int SQLite::AddParams(Value* val, int pos) {
    if ( ! val->present )
        return sqlite3_bind_null(st, pos);

    switch ( val->type ) {
        case TYPE_BOOL: return sqlite3_bind_int(st, pos, val->val.int_val != 0 ? 1 : 0);

        case TYPE_INT: return sqlite3_bind_int(st, pos, val->val.int_val);

        case TYPE_COUNT: return sqlite3_bind_int(st, pos, val->val.uint_val);

        case TYPE_PORT: return sqlite3_bind_int(st, pos, val->val.port_val.port);

        case TYPE_SUBNET: {
            string out = io->Render(val->val.subnet_val);
            return sqlite3_bind_text(st, pos, out.data(), out.size(), SQLITE_TRANSIENT);
        }

        case TYPE_ADDR: {
            string out = io->Render(val->val.addr_val);
            return sqlite3_bind_text(st, pos, out.data(), out.size(), SQLITE_TRANSIENT);
        }

        case TYPE_TIME:
        case TYPE_INTERVAL:
        case TYPE_DOUBLE: return sqlite3_bind_double(st, pos, val->val.double_val);

        case TYPE_ENUM:
        case TYPE_STRING:
        case TYPE_FILE:
        case TYPE_FUNC: {
            if ( ! val->val.string_val.length || val->val.string_val.length == 0 )
                return sqlite3_bind_null(st, pos);

            return sqlite3_bind_text(st, pos, val->val.string_val.data, val->val.string_val.length, SQLITE_TRANSIENT);
        }

        case TYPE_TABLE: {
            ODesc desc;
            desc.Clear();
            desc.EnableEscaping();
            desc.AddEscapeSequence(set_separator);

            if ( ! val->val.set_val.size )
                desc.Add(empty_field);
            else
                for ( zeek_int_t j = 0; j < val->val.set_val.size; j++ ) {
                    if ( j > 0 )
                        desc.AddRaw(set_separator);

                    io->Describe(&desc, val->val.set_val.vals[j], fields[pos - 1]->name);
                }

            desc.RemoveEscapeSequence(set_separator);
            return sqlite3_bind_text(st, pos, (const char*)desc.Bytes(), desc.Len(), SQLITE_TRANSIENT);
        }

        case TYPE_VECTOR: {
            ODesc desc;
            desc.Clear();
            desc.EnableEscaping();
            desc.AddEscapeSequence(set_separator);

            if ( ! val->val.vector_val.size )
                desc.Add(empty_field);
            else
                for ( zeek_int_t j = 0; j < val->val.vector_val.size; j++ ) {
                    if ( j > 0 )
                        desc.AddRaw(set_separator);

                    io->Describe(&desc, val->val.vector_val.vals[j], fields[pos - 1]->name);
                }

            desc.RemoveEscapeSequence(set_separator);
            return sqlite3_bind_text(st, pos, (const char*)desc.Bytes(), desc.Len(), SQLITE_TRANSIENT);
        }

        default: Error(Fmt("unsupported field format %d", val->type)); return 0;
    }
}

bool SQLite::DoWrite(int num_fields, const Field* const* fields, Value** vals) {
    // bind parameters
    for ( int i = 0; i < num_fields; i++ ) {
        if ( checkError(AddParams(vals[i], i + 1)) )
            return false;
    }

    // execute query
    if ( checkError(sqlite3_step(st)) )
        return false;

    // clean up and make ready for next query execution
    if ( checkError(sqlite3_clear_bindings(st)) )
        return false;

    if ( checkError(sqlite3_reset(st)) )
        return false;

    return true;
}

bool SQLite::DoRotate(const char* rotated_path, double open, double close, bool terminating) {
    if ( ! FinishedRotation("/dev/null", Info().path, open, close, terminating) ) {
        Error(Fmt("error rotating %s", Info().path));
        return false;
    }

    return true;
}

} // namespace zeek::logging::writer::detail
