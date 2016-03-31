##! Various data structure definitions for use with Bro's communication system.

@load ./main

module Broker;

export {

	## Whether a data store query could be completed or not.
	type QueryStatus: enum {
		SUCCESS,
		FAILURE,
	};

	## An expiry time for a key-value pair inserted in to a data store.
	type ExpiryTime: record {
		## Absolute point in time at which to expire the entry.
		absolute: time &optional;
		## A point in time relative to the last modification time at which
		## to expire the entry.  New modifications will delay the expiration.
		since_last_modification: interval &optional;
	};

	## The result of a data store query.
	type QueryResult: record {
		## Whether the query completed or not.
		status: Broker::QueryStatus;
		## The result of the query.  Certain queries may use a particular
		## data type (e.g. querying store size always returns a count, but
		## a lookup may return various data types).
		result: Broker::Data;
	};

	## Options to tune the SQLite storage backend.
	type SQLiteOptions: record {
		## File system path of the database.
		path: string &default = "store.sqlite";
	};

	## Options to tune the RocksDB storage backend.
	type RocksDBOptions: record {
		## File system path of the database.
		path: string &default = "store.rocksdb";
	};

	## Options to tune the particular storage backends.
	type BackendOptions: record {
		sqlite: SQLiteOptions &default = SQLiteOptions();
		rocksdb: RocksDBOptions &default = RocksDBOptions();
	};
}
