##! PostgreSQL storage backend support

@load base/frameworks/storage/main

module Storage::Backend::PostgreSQL;

export {
	## Options record for the built-in PostgreSQL backend.
	type Options: record {
		## PostgreSQL connection string for connecting to the database using the
		## standard format:
		## postgresql://[user[:password]@]host[:port][/dbname][?param1=value1&...]
		connection_string: string;

		## Name of the table used for storing data. It is possible to use the same
		## database file for two separate tables, as long as the this value is
		## different between the two.
		table_name: string;

		## The timeout for the connection to the database. This is set
		## per-connection. It is equivalent to setting a ``busy_timeout`` pragma
		## value, but that value will be ignored in favor of this field.
		busy_timeout: interval &default=5 secs;
	};
}

redef record Storage::BackendOptions += {
	postgresql: Storage::Backend::PostgreSQL::Options &optional;
};
