##! SQLite storage backend support

@load base/frameworks/storage/main

module Storage::Backend::SQLite;

export {
	## Options record for the built-in SQLite backend.
	type Options: record {
		## Path to the database file on disk. Setting this to ":memory:"
		## will tell SQLite to use an in-memory database. Relative paths
		## will be opened relative to the directory where Zeek was
		## started from. Zeek will not create intermediate directories
		## if they do not already exist. See
		## https://www.sqlite.org/c3ref/open.html for more rules on
		## paths that can be passed here.
		database_path: string;

		## Name of the table used for storing data.
		table_name: string;

		## Key/value table for passing tuning parameters when opening
		## the database.  These must be pairs that can be passed to the
		## ``pragma`` command in sqlite.
		tuning_params: table[string] of string &default=table(
			["journal_mode"] = "WAL",
			["synchronous"] = "normal",
			["temp_store"] = "memory"
		);
	};
}
