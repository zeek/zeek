##! Interface for the SQLite log writer. Redefinable options are available
##! to tweak the output format of the SQLite reader.
##!
##! See :doc:`/frameworks/logging-input-sqlite` for an introduction on how to
##! use the SQLite log writer.
##!
##! The SQL writer currently supports one writer-specific filter option via
##! ``config``: setting ``tablename`` sets the name of the table that is used
##! or created in the SQLite database. An example for this is given in the
##! introduction mentioned above.

module LogSQLite;

export {
	## Separator between set elements.
	const set_separator = Log::set_separator &redef;

	## String to use for an unset &optional field.
	const unset_field = Log::unset_field &redef;

	## String to use for empty fields. This should be different from
	## *unset_field* to make the output unambiguous.
	const empty_field = Log::empty_field &redef;

	## Values supported for SQLite's PRAGMA synchronous statement.
	type SQLiteSynchronous: enum {
		SQLITE_SYNCHRONOUS_DEFAULT,
		SQLITE_SYNCHRONOUS_OFF,
		SQLITE_SYNCHRONOUS_NORMAL,
		SQLITE_SYNCHRONOUS_FULL,
		SQLITE_SYNCHRONOUS_EXTRA,
	};

	## Values supported for SQLite's PRAGMA journal_mode statement.
	type SQLiteJournalMode: enum {
		SQLITE_JOURNAL_MODE_DEFAULT,
		SQLITE_JOURNAL_MODE_DELETE,
		SQLITE_JOURNAL_MODE_TRUNCATE,
		SQLITE_JOURNAL_MODE_PERSIST,
		SQLITE_JOURNAL_MODE_MEMORY,
		SQLITE_JOURNAL_MODE_WAL,
		SQLITE_JOURNAL_MODE_OFF,
	};

	## If changed from SQLITE_SYNCHRONOUS_DEFAULT, runs the PRAGMA synchronous
	## statement with the provided value after connecting to the SQLite database. See
	## `SQLite's synchronous documentation <https://www.sqlite.org/pragma.html#pragma_synchronous>`_
	## for more details around performance and data safety trade offs.
	const synchronous = SQLITE_SYNCHRONOUS_DEFAULT &redef;

	## If changed from SQLITE_JOURNAL_MODE_DEFAULT, runs the PRAGMA
	## journal_mode statement with the provided value after connecting to
	## the SQLite database.
	## `SQLite's journal_mode documentation <https://www.sqlite.org/pragma.html#pragma_journal_mode>`_
	## for more details around performance, data safety trade offs
	## and interaction with the PRAGMA synchronous statement.
	const journal_mode = SQLITE_JOURNAL_MODE_DEFAULT &redef;
}

