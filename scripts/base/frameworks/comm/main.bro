##! Various data structure definitions for use with Bro's communication system.

module BrokerComm;

export {

	## A name used to identify this endpoint to peers.
	## .. bro:see:: BrokerComm::connect BrokerComm::listen
	const endpoint_name = "" &redef;

	## Change communication behavior.
	type EndpointFlags: record {
		## Whether to restrict message topics that can be published to peers.
		auto_publish: bool &default = T;
		## Whether to restrict what message topics or data store identifiers
		## the local endpoint advertises to peers (e.g. subscribing to
		## events or making a master data store available).
		auto_advertise: bool &default = T;
	};

	## Fine-grained tuning of communication behavior for a particular message.
	type SendFlags: record {
		## Send the message to the local endpoint.
		self: bool &default = F;
		## Send the message to peer endpoints that advertise interest in
		## the topic associated with the message.
		peers: bool &default = T;
		## Send the message to peer endpoints even if they don't advertise
		## interest in the topic associated with the message.
		unsolicited: bool &default = F;
	};

	## Opaque communication data.
	type Data: record {
		d: opaque of BrokerComm::Data &optional;
	};

	## Opaque communication data.
	type DataVector: vector of BrokerComm::Data;

	## Opaque event communication data.
	type EventArgs: record {
		## The name of the event.  Not set if invalid event or arguments.
		name: string &optional;
		## The arguments to the event.
		args: DataVector;
	};

	## Opaque communication data used as a convenient way to wrap key-value
	## pairs that comprise table entries.
	type TableItem : record {
		key: BrokerComm::Data;
		val: BrokerComm::Data;
	};
}

module BrokerStore;

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
		status: BrokerStore::QueryStatus;
		## The result of the query.  Certain queries may use a particular
		## data type (e.g. querying store size always returns a count, but
		## a lookup may return various data types).
		result: BrokerComm::Data;
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
