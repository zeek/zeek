##! SQLite storage backend support

@load base/frameworks/storage/main

module Storage::Backend::SQLite;

export {
	## Options record for the built-in SQLite backend.
	type Options: record {
		## Path to the database file on disk. Setting this to ":memory:" will tell
		## SQLite to use an in-memory database. Relative paths will be opened
		## relative to the directory where Zeek was started from. Zeek will not
		## create intermediate directories if they do not already exist. See
		## https://www.sqlite.org/c3ref/open.html for more rules on paths that can
		## be passed here.
		database_path: string;

		## Name of the table used for storing data. It is possible to use the same
		## database file for two separate tables, as long as the this value is
		## different between the two.
		table_name: string;

		## The timeout for the connection to the database. This is set
		## per-connection. It is equivalent to setting a ``busy_timeout`` pragma
		## value, but that value will be ignored in favor of this field.
		busy_timeout: interval &default=5 secs;

		## Key/value table for passing pragma commands when opening the database.
		## These must be pairs that can be passed to the ``pragma`` command in
		## sqlite. The ``integrity_check`` pragma is run automatically and does
		## not need to be included here. For pragmas without a second argument,
		## set the value to an empty string. Setting the ``busy_timeout`` pragma
		## here will be ignored.
		pragma_commands: table[string] of string &ordered &default=table(
			["integrity_check"] = "",
			["journal_mode"] = "WAL",
			["synchronous"] = "normal",
			["temp_store"] = "memory"
		) &ordered;

		## The total amount of time that an SQLite backend will spend attempting
		## to run an individual pragma command before giving up and returning an
		## initialization error. Setting this to zero will result in the backend
		## attempting forever until success.
		pragma_timeout: interval &default=500 msec;

		## The amount of time that at SQLite backend will wait between failures
		## to run an individual pragma command.
		pragma_wait_on_busy: interval &default=5 msec;
	};
}

redef record Storage::BackendOptions += {
	sqlite: Storage::Backend::SQLite::Options &optional;
};
