# This test exercises the SQLIte pragmas for synchronous and jornal_mode.
# Sadly, most of these do not have a way to test that they succeeded. So
# we mostly do the inverse test - if there are no error messages in .stderr
# everything should be fine.
#
# We can test for WAL journaling mode, as this persists and can be queried from
# the sqlite file.

# @TEST-REQUIRES: which sqlite3
# @TEST-REQUIRES: has-writer Zeek::SQLiteWriter
# @TEST-GROUP: sqlite
#
# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT Log::default_writer=Log::WRITER_SQLITE LogSQLite::synchronous=LogSQLite::SQLITE_SYNCHRONOUS_EXTRA LogSQLite::journal_mode=LogSQLite::SQLITE_JOURNAL_MODE_DELETE
# @TEST-EXEC: echo "Should be delete" > results
# @TEST-EXEC: sqlite3 http.sqlite "PRAGMA journal_mode" >> results
# @TEST-EXEC: rm http.sqlite
# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT Log::default_writer=Log::WRITER_SQLITE LogSQLite::synchronous=LogSQLite::SQLITE_SYNCHRONOUS_OFF LogSQLite::journal_mode=LogSQLite::SQLITE_JOURNAL_MODE_TRUNCATE
# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT Log::default_writer=Log::WRITER_SQLITE LogSQLite::synchronous=LogSQLite::SQLITE_SYNCHRONOUS_NORMAL LogSQLite::journal_mode=LogSQLite::SQLITE_JOURNAL_MODE_PERSIST
# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT Log::default_writer=Log::WRITER_SQLITE LogSQLite::synchronous=LogSQLite::SQLITE_SYNCHRONOUS_EXTRA LogSQLite::journal_mode=LogSQLite::SQLITE_JOURNAL_MODE_MEMORY
# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT Log::default_writer=Log::WRITER_SQLITE LogSQLite::synchronous=LogSQLite::SQLITE_SYNCHRONOUS_EXTRA LogSQLite::journal_mode=LogSQLite::SQLITE_JOURNAL_MODE_WAL
# @TEST-EXEC: echo "Should be WAL" >> results
# @TEST-EXEC: sqlite3 http.sqlite "PRAGMA journal_mode" >> results
# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT Log::default_writer=Log::WRITER_SQLITE LogSQLite::synchronous=LogSQLite::SQLITE_SYNCHRONOUS_FULL LogSQLite::journal_mode=LogSQLite::SQLITE_JOURNAL_MODE_OFF
# @TEST-EXEC: btest-diff results
# @TEST-EXEC: echo "end of stderr" >> .stderr # btest-diff does not like the canonifier to have an empty output
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v tablename' btest-diff .stderr

@load base/protocols/http
