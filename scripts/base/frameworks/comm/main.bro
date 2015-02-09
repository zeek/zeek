
module Comm;

export {

	const endpoint_name = "" &redef;

	type EndpointFlags: record {
		auto_publish: bool &default = T;
		auto_advertise: bool &default = T;
	};

	type SendFlags: record {
		self: bool &default = F;
		peers: bool &default = T;
		unsolicited: bool &default = F;
	};

	type Data: record {
		d: opaque of Comm::Data &optional;
	};

	type DataVector: vector of Comm::Data;

	type EventArgs: record {
		name: string &optional;  # nil for invalid event/args.
		args: DataVector;
	};

	type Comm::TableItem : record {
		key: Comm::Data;
		val: Comm::Data;
	};
}

module Store;

export {

	type QueryStatus: enum {
		SUCCESS,
		FAILURE,
	};

	type ExpiryTime: record {
		absolute: time &optional;
		since_last_modification: interval &optional;
	};

	type QueryResult: record {
		status: Store::QueryStatus;
		result: Comm::Data;
	};

	type SQLiteOptions: record {
		path: string &default = "store.sqlite";
	};

	type RocksDBOptions: record {
		path: string &default = "store.rocksdb";
		use_merge_operator: bool &default = F;
	};

	type BackendOptions: record {
		sqlite: SQLiteOptions &default = SQLiteOptions();
		rocksdb: RocksDBOptions &default = RocksDBOptions();
	};
}
