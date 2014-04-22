#
# @TEST-REQUIRES: which sqlite3
# @TEST-REQUIRES: has-writer SQLite
# @TEST-GROUP: sqlite
#
# @TEST-EXEC: bro -r $TRACES/wikipedia.trace Log::default_writer=Log::WRITER_SQLITE
# @TEST-EXEC: sqlite3 conn.sqlite 'select * from conn order by ts' | sort -n > conn.select
# @TEST-EXEC: sqlite3 http.sqlite 'select * from http order by ts' | sort -n > http.select
# @TEST-EXEC: btest-diff conn.select
# @TEST-EXEC: btest-diff http.select
