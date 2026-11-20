
# @TEST-DOC: SQLite writer quotes the table name instead of executing it as SQL (#5933)
#
# @TEST-REQUIRES: which sqlite3
# @TEST-REQUIRES: has-writer Zeek::SQLiteWriter
# @TEST-GROUP: sqlite
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: sqlite3 sqlite-injection.sqlite "select name from sqlite_master where type='table'" > tables
# @TEST-EXEC: sqlite3 sqlite-path-test.sqlite 'select * from "sqlite-path-test"' >> tables
# @TEST-EXEC: btest-diff tables

@load base/frameworks/logging/writers/sqlite

module SQLiteTableName;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        msg: string &log;
    };
}

event zeek_init()
    {
    local cfg: table[string] of string = table(
        ["tablename"] = "mainlog (msg text); CREATE TABLE injected(marker text); --"
    );

    Log::create_stream(SQLiteTableName::LOG, [$columns=SQLiteTableName::Info]);
    Log::remove_default_filter(SQLiteTableName::LOG);

    Log::add_filter(SQLiteTableName::LOG,
        [$name="sqlite", $path="sqlite-injection", $writer=Log::WRITER_SQLITE, $config=cfg]);

    Log::add_filter(SQLiteTableName::LOG,
        [$name="sqlite-path", $path="sqlite-path-test", $writer=Log::WRITER_SQLITE]);

    Log::write(SQLiteTableName::LOG, [$msg="trigger"]);
    }
