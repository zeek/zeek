##! Various data structure definitions for use with Bro's communication system.

@load ./main
@load base/bif/data.bif

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

	## Enumerates the possible storage backends.
	type BackendType: enum {
		MEMORY,
		SQLITE,
		ROCKSDB,
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

@ifdef ( Broker::__enable )

	## Create a master data store which contains key-value pairs.
	##
	## id: a unique name for the data store.
	##
	## b: the storage backend to use.
	##
	## options: tunes how some storage backends operate.
	##
	## Returns: a handle to the data store.
	global create_master: function(id: string, b: BackendType &default = MEMORY,
	                               options: BackendOptions &default = BackendOptions()): opaque of Broker::Handle;

	## Create a clone of a master data store which may live with a remote peer.
	## A clone automatically synchronizes to the master by automatically
	## receiving modifications and applying them locally.  Direct modifications
	## are not possible, they must be sent through the master store, which then
	## automatically broadcasts the changes out to clones.  But queries may be
	## made directly against the local cloned copy, which may be resolved
	## quicker than reaching out to a remote master store.
	##
	## id: the unique name which identifies the master data store.
	##
	## b: the storage backend to use.
	##
	## options: tunes how some storage backends operate.
	##
	## resync: the interval at which to re-attempt synchronizing with the master
	##         store should the connection be lost.  If the clone has not yet
	##         synchronized for the first time, updates and queries queue up
	##         until the synchronization completes.  After, if the connection
	##         to the master store is lost, queries continue to use the clone's
	##         version, but updates will be lost until the master is once again
	##         available.
	##
	## Returns: a handle to the data store.
	global create_clone: function(id: string, b: BackendType &default = MEMORY,
	                              options: BackendOptions &default = BackendOptions(),
	                              resync: interval &default = 1sec): opaque of Broker::Handle;

	## Create a frontend interface to an existing master data store that allows
	## querying and updating its contents.
	##
	## id: the unique name which identifies the master data store.
	##
	## Returns: a handle to the data store.
	global create_frontend: function(id: string): opaque of Broker::Handle;

	## Close a data store.
	##
	## h: a data store handle.
	##
	## Returns: true if store was valid and is now closed.  The handle can no
	##          longer be used for data store operations.
	global close_by_handle: function(h: opaque of Broker::Handle): bool;

	###########################
	# non-blocking update API #
	###########################

	## Insert a key-value pair in to the store.
	##
	## h: the handle of the store to modify.
	##
	## k: the key to insert.
	##
	## v: the value to insert.
	##
	## e: the expiration time of the key-value pair.
	##
	## Returns: false if the store handle was not valid.
	global insert: function(h: opaque of Broker::Handle,
	                        k: Broker::Data, v: Broker::Data,
	                        e: Broker::ExpiryTime &default = Broker::ExpiryTime()): bool;

	## Remove a key-value pair from the store.
	##
	## h: the handle of the store to modify.
	##
	## k: the key to remove.
	##
	## Returns: false if the store handle was not valid.
	global erase: function(h: opaque of Broker::Handle, k: Broker::Data): bool;

	## Remove all key-value pairs from the store.
	##
	## h: the handle of the store to modify.
	##
	## Returns: false if the store handle was not valid.
	global clear: function(h: opaque of Broker::Handle): bool;

	## Increment an integer value in a data store.
	##
	## h: the handle of the store to modify.
	##
	## k: the key whose associated value is to be modified.
	##
	## by: the amount to increment the value by.  A non-existent key will first
	##     create it with an implicit value of zero before incrementing.
	##
	## Returns: false if the store handle was not valid.
	global increment: function(h: opaque of Broker::Handle,
	                           k: Broker::Data, by: int &default = +1): bool;

	## Decrement an integer value in a data store.
	##
	## h: the handle of the store to modify.
	##
	## k: the key whose associated value is to be modified.
	##
	## by: the amount to decrement the value by.  A non-existent key will first
	##     create it with an implicit value of zero before decrementing.
	##
	## Returns: false if the store handle was not valid.
	global decrement: function(h: opaque of Broker::Handle,
	                           k: Broker::Data, by: int &default = +1): bool;

	## Add an element to a set value in a data store.
	##
	## h: the handle of the store to modify.
	##
	## k: the key whose associated value is to be modified.
	##
	## element: the element to add to the set.  A non-existent key will first
	##          create it with an implicit empty set value before modifying.
	##
	## Returns: false if the store handle was not valid.
	global add_to_set: function(h: opaque of Broker::Handle,
	                            k: Broker::Data, element: Broker::Data): bool;

	## Remove an element from a set value in a data store.
	##
	## h: the handle of the store to modify.
	##
	## k: the key whose associated value is to be modified.
	##
	## element: the element to remove from the set.  A non-existent key will
	##          implicitly create an empty set value associated with the key.
	##
	## Returns: false if the store handle was not valid.
	global remove_from_set: function(h: opaque of Broker::Handle,
	                                 k: Broker::Data, element: Broker::Data): bool;

	## Add a new item to the head of a vector value in a data store.
	##
	## h: the handle of store to modify.
	##
	## k: the key whose associated value is to be modified.
	##
	## items: the element to insert in to the vector.  A non-existent key will
	##        first create an empty vector value before modifying.
	##
	## Returns: false if the store handle was not valid.
	global push_left: function(h: opaque of Broker::Handle, k: Broker::Data,
	                           items: Broker::DataVector): bool;

	## Add a new item to the tail of a vector value in a data store.
	##
	## h: the handle of store to modify.
	##
	## k: the key whose associated value is to be modified.
	##
	## items: the element to insert in to the vector.  A non-existent key will
	##        first create an empty vector value before modifying.
	##
	## Returns: false if the store handle was not valid.
	global push_right: function(h: opaque of Broker::Handle, k: Broker::Data,
	                            items: Broker::DataVector): bool;

	##########################
	# non-blocking query API #
	##########################

	## Pop the head of a data store vector value.
	##
	## h: the handle of the store to query.
	##
	## k: the key associated with the vector to modify.
	##
	## Returns: the result of the query.
	global pop_left: function(h: opaque of Broker::Handle,
	                          k: Broker::Data): QueryResult;

	## Pop the tail of a data store vector value.
	##
	## h: the handle of the store to query.
	##
	## k: the key associated with the vector to modify.
	##
	## Returns: the result of the query.
	global pop_right: function(h: opaque of Broker::Handle,
	                           k: Broker::Data): QueryResult;

	## Lookup the value associated with a key in a data store.
	##
	## h: the handle of the store to query.
	##
	## k: the key to lookup.
	##
	## Returns: the result of the query.
	global lookup: function(h: opaque of Broker::Handle,
	                       k: Broker::Data): QueryResult;

	## Check if a data store contains a given key.
	##
	## h: the handle of the store to query.
	##
	## k: the key to check for existence.
	##
	## Returns: the result of the query (uses :bro:see:`Broker::BOOL`).
	global exists: function(h: opaque of Broker::Handle,
	                        k: Broker::Data): QueryResult;

	## Retrieve all keys in a data store.
	##
	## h: the handle of the store to query.
	##
	## Returns: the result of the query (uses :bro:see:`Broker::VECTOR`).
	global keys: function(h: opaque of Broker::Handle): QueryResult;

	## Get the number of key-value pairs in a data store.
	##
	## h: the handle of the store to query.
	##
	## Returns: the result of the query (uses :bro:see:`Broker::COUNT`).
	global size: function(h: opaque of Broker::Handle): QueryResult;

	##########################
	# data API               #
	##########################

	## Convert any Bro value to communication data.
	##
	## d: any Bro value to attempt to convert (not all types are supported).
	##
	## Returns: the converted communication data.  The returned record's optional
	##          field will not be set if the conversion was not possible (this can
	##          happen if the Bro data type does not support being converted to
	##          communication data).
	global data: function(d: any): Broker::Data;

	## Retrieve the type of data associated with communication data.
	##
	## d: the communication data.
	##
	## Returns: the data type associated with the communication data.
	global data_type: function(d: Broker::Data): Broker::DataType;

	## Convert communication data with a type of :bro:see:`Broker::BOOL` to
	## an actual Bro value.
	##
	## d: the communication data to convert.
	##
	## Returns: the value retrieved from the communication data.
	global refine_to_bool: function(d: Broker::Data): bool;

	## Convert communication data with a type of :bro:see:`Broker::INT` to
	## an actual Bro value.
	##
	## d: the communication data to convert.
	##
	## Returns: the value retrieved from the communication data.
	global refine_to_int: function(d: Broker::Data): int;

	## Convert communication data with a type of :bro:see:`Broker::COUNT` to
	## an actual Bro value.
	##
	## d: the communication data to convert.
	##
	## Returns: the value retrieved from the communication data.
	global refine_to_count: function(d: Broker::Data): count;

	## Convert communication data with a type of :bro:see:`Broker::DOUBLE` to
	## an actual Bro value.
	##
	## d: the communication data to convert.
	##
	## Returns: the value retrieved from the communication data.
	global refine_to_double: function(d: Broker::Data): double;

	## Convert communication data with a type of :bro:see:`Broker::STRING` to
	## an actual Bro value.
	##
	## d: the communication data to convert.
	##
	## Returns: the value retrieved from the communication data.
	global refine_to_string: function(d: Broker::Data): string;

	## Convert communication data with a type of :bro:see:`Broker::ADDR` to
	## an actual Bro value.
	##
	## d: the communication data to convert.
	##
	## Returns: the value retrieved from the communication data.
	global refine_to_addr: function(d: Broker::Data): addr;

	## Convert communication data with a type of :bro:see:`Broker::SUBNET` to
	## an actual Bro value.
	##
	## d: the communication data to convert.
	##
	## Returns: the value retrieved from the communication data.
	global refine_to_subnet: function(d: Broker::Data): subnet;

	## Convert communication data with a type of :bro:see:`Broker::PORT` to
	## an actual Bro value.
	##
	## d: the communication data to convert.
	##
	## Returns: the value retrieved from the communication data.
	global refine_to_port: function(d: Broker::Data): port;

	## Convert communication data with a type of :bro:see:`Broker::TIME` to
	## an actual Bro value.
	##
	## d: the communication data to convert.
	##
	## Returns: the value retrieved from the communication data.
	global refine_to_time: function(d: Broker::Data): time;

	## Convert communication data with a type of :bro:see:`Broker::INTERVAL` to
	## an actual Bro value.
	##
	## d: the communication data to convert.
	##
	## Returns: the value retrieved from the communication data.
	global refine_to_interval: function(d: Broker::Data): interval;

	## Convert communication data with a type of :bro:see:`Broker::ENUM` to
	## the name of the enum value.  :bro:see:`lookup_ID` may be used to convert
	## the name to the actual enum value.
	##
	## d: the communication data to convert.
	##
	## Returns: the enum name retrieved from the communication data.
	global refine_to_enum_name: function(d: Broker::Data): string;

	## Create communication data of type "set".
	global set_create: function(): Broker::Data;

	## Remove all elements within a set.
	##
	## s: the set to clear.
	##
	## Returns: always true.
	global set_clear: function(s: Broker::Data): bool;

	## Get the number of elements within a set.
	##
	## s: the set to query.
	##
	## Returns: the number of elements in the set.
	global set_size: function(s: Broker::Data): count;

	## Check if a set contains a particular element.
	##
	## s: the set to query.
	##
	## key: the element to check for existence.
	##
	## Returns: true if the key exists in the set.
	global set_contains: function(s: Broker::Data, key: Broker::Data): bool;

	## Insert an element into a set.
	##
	## s: the set to modify.
	##
	## key: the element to insert.
	##
	## Returns: true if the key was inserted, or false if it already existed.
	global set_insert: function(s: Broker::Data, key: Broker::Data): bool;

	## Remove an element from a set.
	##
	## s: the set to modify.
	##
	## key: the element to remove.
	##
	## Returns: true if the element existed in the set and is now removed.
	global set_remove: function(s: Broker::Data, key: Broker::Data): bool;

	## Create an iterator for a set.  Note that this makes a copy of the set
	## internally to ensure the iterator is always valid.
	##
	## s: the set to iterate over.
	##
	## Returns: an iterator.
	global set_iterator: function(s: Broker::Data): opaque of Broker::SetIterator;

	## Check if there are no more elements to iterate over.
	##
	## it: an iterator.
	##
	## Returns: true if there are no more elements to iterator over, i.e.
	##          the iterator is one-past-the-final-element.
	global set_iterator_last: function(it: opaque of Broker::SetIterator): bool;

	## Advance an iterator.
	##
	## it: an iterator.
	##
	## Returns: true if the iterator, after advancing, still references an element
	##          in the collection.  False if the iterator, after advancing, is
	##          one-past-the-final-element.
	global set_iterator_next: function(it: opaque of Broker::SetIterator): bool;

	## Retrieve the data at an iterator's current position.
	##
	## it: an iterator.
	##
	## Returns: element in the collection that the iterator currently references.
	global set_iterator_value: function(it: opaque of Broker::SetIterator): Broker::Data;

	## Create communication data of type "table".
	global table_create: function(): Broker::Data;

	## Remove all elements within a table.
	##
	## t: the table to clear.
	##
	## Returns: always true.
	global table_clear: function(t: Broker::Data): bool;

	## Get the number of elements within a table.
	##
	## t: the table to query.
	##
	## Returns: the number of elements in the table.
	global table_size: function(t: Broker::Data): count;

	## Check if a table contains a particular key.
	##
	## t: the table to query.
	##
	## key: the key to check for existence.
	##
	## Returns: true if the key exists in the table.
	global table_contains: function(t: Broker::Data, key: Broker::Data): bool;

	## Insert a key-value pair into a table.
	##
	## t: the table to modify.
	##
	## key: the key at which to insert the value.
	##
	## val: the value to insert.
	##
	## Returns: true if the key-value pair was inserted, or false if the key
	##          already existed in the table.
	global table_insert: function(t: Broker::Data, key: Broker::Data, val: Broker::Data): Broker::Data;

	## Remove a key-value pair from a table.
	##
	## t: the table to modify.
	##
	## key: the key to remove from the table.
	##
	## Returns: the value associated with the key.  If the key did not exist, then
	##          the optional field of the returned record is not set.
	global table_remove: function(t: Broker::Data, key: Broker::Data): Broker::Data;

	## Retrieve a value from a table.
	##
	## t: the table to query.
	##
	## key: the key to lookup.
	##
	## Returns: the value associated with the key.  If the key did not exist, then
	##          the optional field of the returned record is not set.
	global table_lookup: function(t: Broker::Data, key: Broker::Data): Broker::Data;

	## Create an iterator for a table.  Note that this makes a copy of the table
	## internally to ensure the iterator is always valid.
	##
	## t: the table to iterate over.
	##
	## Returns: an iterator.
	global table_iterator: function(t: Broker::Data): opaque of Broker::TableIterator;

	## Check if there are no more elements to iterate over.
	##
	## it: an iterator.
	##
	## Returns: true if there are no more elements to iterator over, i.e.
	##          the iterator is one-past-the-final-element.
	global table_iterator_last: function(it: opaque of Broker::TableIterator): bool;

	## Advance an iterator.
	##
	## it: an iterator.
	##
	## Returns: true if the iterator, after advancing, still references an element
	##          in the collection.  False if the iterator, after advancing, is
	##          one-past-the-final-element.
	global table_iterator_next: function(it: opaque of Broker::TableIterator): bool;

	## Retrieve the data at an iterator's current position.
	##
	## it: an iterator.
	##
	## Returns: element in the collection that the iterator currently references.
	global table_iterator_value: function(it: opaque of Broker::TableIterator): Broker::TableItem;

	## Create communication data of type "vector".
	global vector_create: function(): Broker::Data;

	## Remove all elements within a vector.
	##
	## v: the vector to clear.
	##
	## Returns: always true.
	global vector_clear: function(v: Broker::Data): bool;

	## Get the number of elements within a vector.
	##
	## v: the vector to query.
	##
	## Returns: the number of elements in the vector.
	global vector_size: function(v: Broker::Data): count;

	## Insert an element into a vector at a particular position, possibly displacing
	## existing elements (insertion always grows the size of the vector by one).
	##
	## v: the vector to modify.
	##
	## d: the element to insert.
	##
	## idx: the index at which to insert the data.  If it is greater than the
	##      current size of the vector, the element is inserted at the end.
	##
	## Returns: always true.
	global vector_insert: function(v: Broker::Data, d: Broker::Data, idx: count): bool;

	## Replace an element in a vector at a particular position.
	##
	## v: the vector to modify.
	##
	## d: the element to insert.
	##
	## idx: the index to replace.
	##
	## Returns: the value that was just evicted.  If the index was larger than any
	##          valid index, the optional field of the returned record is not set.
	global vector_replace: function(v: Broker::Data, d: Broker::Data, idx: count): Broker::Data;

	## Remove an element from a vector at a particular position.
	##
	## v: the vector to modify.
	##
	## idx: the index to remove.
	##
	## Returns: the value that was just evicted.  If the index was larger than any
	##          valid index, the optional field of the returned record is not set.
	global vector_remove: function(v: Broker::Data, idx: count): Broker::Data;

	## Lookup an element in a vector at a particular position.
	##
	## v: the vector to query.
	##
	## idx: the index to lookup.
	##
	## Returns: the value at the index.  If the index was larger than any
	##          valid index, the optional field of the returned record is not set.
	global vector_lookup: function(v: Broker::Data, idx: count): Broker::Data;

	## Create an iterator for a vector.  Note that this makes a copy of the vector
	## internally to ensure the iterator is always valid.
	##
	## v: the vector to iterate over.
	##
	## Returns: an iterator.
	global vector_iterator: function(v: Broker::Data): opaque of Broker::VectorIterator;

	## Check if there are no more elements to iterate over.
	##
	## it: an iterator.
	##
	## Returns: true if there are no more elements to iterator over, i.e.
	##          the iterator is one-past-the-final-element.
	global vector_iterator_last: function(it: opaque of Broker::VectorIterator): bool;

	## Advance an iterator.
	##
	## it: an iterator.
	##
	## Returns: true if the iterator, after advancing, still references an element
	##          in the collection.  False if the iterator, after advancing, is
	##          one-past-the-final-element.
	global vector_iterator_next: function(it: opaque of Broker::VectorIterator): bool;

	## Retrieve the data at an iterator's current position.
	##
	## it: an iterator.
	##
	## Returns: element in the collection that the iterator currently references.
	global vector_iterator_value: function(it: opaque of Broker::VectorIterator): Broker::Data;

	## Create communication data of type "record".
	##
	## sz: the number of fields in the record.
	##
	## Returns: record data, with all fields uninitialized.
	global record_create: function(sz: count): Broker::Data;

	## Get the number of fields within a record.
	##
	## r: the record to query.
	##
	## Returns: the number of fields in the record.
	global record_size: function(r: Broker::Data): count;

	## Replace a field in a record at a particular position.
	##
	## r: the record to modify.
	##
	## d: the new field value to assign.
	##
	## idx: the index to replace.
	##
	## Returns: false if the index was larger than any valid index, else true.
	global record_assign: function(r: Broker::Data, d: Broker::Data, idx: count): bool;

	## Lookup a field in a record at a particular position.
	##
	## r: the record to query.
	##
	## idx: the index to lookup.
	##
	## Returns: the value at the index.  The optional field of the returned record
	##          may not be set if the field of the record has no value or if the
	##          index was not valid.
	global record_lookup: function(r: Broker::Data, idx: count): Broker::Data;

	## Create an iterator for a record.  Note that this makes a copy of the record
	## internally to ensure the iterator is always valid.
	##
	## r: the record to iterate over.
	##
	## Returns: an iterator.
	global record_iterator: function(r: Broker::Data): opaque of Broker::RecordIterator;

	## Check if there are no more elements to iterate over.
	##
	## it: an iterator.
	##
	## Returns: true if there are no more elements to iterator over, i.e.
	##          the iterator is one-past-the-final-element.
	global record_iterator_last: function(it: opaque of Broker::RecordIterator): bool;

	## Advance an iterator.
	##
	## it: an iterator.
	##
	## Returns: true if the iterator, after advancing, still references an element
	##          in the collection.  False if the iterator, after advancing, is
	##          one-past-the-final-element.
	global record_iterator_next: function(it: opaque of Broker::RecordIterator): bool;

	## Retrieve the data at an iterator's current position.
	##
	## it: an iterator.
	##
	## Returns: element in the collection that the iterator currently references.
	global record_iterator_value: function(it: opaque of Broker::RecordIterator): Broker::Data;

@endif
}

@load base/bif/store.bif

module Broker;

@ifdef ( Broker::__enable )

function create_master(id: string, b: BackendType &default = MEMORY,
                       options: BackendOptions &default = BackendOptions()): opaque of Broker::Handle
	{
	return __create_master(id, b, options);
	}

function create_clone(id: string, b: BackendType &default = MEMORY,
                      options: BackendOptions &default = BackendOptions(),
                      resync: interval &default = 1sec): opaque of Broker::Handle
	{
	return __create_clone(id, b, options, resync);
	}

function create_frontend(id: string): opaque of Broker::Handle
	{
	return __create_frontend(id);
	}

function close_by_handle(h: opaque of Broker::Handle): bool
	{
	return __close_by_handle(h);
	}

function insert(h: opaque of Broker::Handle, k: Broker::Data, v: Broker::Data,
                e: Broker::ExpiryTime &default = Broker::ExpiryTime()): bool
	{
	return __insert(h, k, v, e);
	}

function erase(h: opaque of Broker::Handle, k: Broker::Data): bool
	{
	return __erase(h, k);
	}

function clear(h: opaque of Broker::Handle): bool
	{
	return __clear(h);
	}

function increment(h: opaque of Broker::Handle,
                           k: Broker::Data, by: int &default = +1): bool
	{
	return __increment(h, k, by);
	}

function decrement(h: opaque of Broker::Handle,
                           k: Broker::Data, by: int &default = +1): bool
	{
	return __decrement(h, k, by);
	}

function add_to_set(h: opaque of Broker::Handle,
                            k: Broker::Data, element: Broker::Data): bool
	{
	return __add_to_set(h, k, element);
	}

function remove_from_set(h: opaque of Broker::Handle,
                                 k: Broker::Data, element: Broker::Data): bool
	{
	return __remove_from_set(h, k, element);
	}

function push_left(h: opaque of Broker::Handle, k: Broker::Data,
                           items: Broker::DataVector): bool
	{
	return __push_left(h, k, items);
	}

function push_right(h: opaque of Broker::Handle, k: Broker::Data,
                            items: Broker::DataVector): bool
	{
	return __push_right(h, k, items);
	}

function pop_left(h: opaque of Broker::Handle, k: Broker::Data): QueryResult
	{
	return __pop_left(h, k);
	}

function pop_right(h: opaque of Broker::Handle, k: Broker::Data): QueryResult
	{
	return __pop_right(h, k);
	}

function lookup(h: opaque of Broker::Handle, k: Broker::Data): QueryResult
	{
	return __lookup(h, k);
	}

function exists(h: opaque of Broker::Handle, k: Broker::Data): QueryResult
	{
	return __exists(h, k);
	}

function keys(h: opaque of Broker::Handle): QueryResult
	{
	return __keys(h);
	}

function size(h: opaque of Broker::Handle): QueryResult
	{
	return __size(h);
	}

function data(d: any): Broker::Data
	{
	return __data(d);
	}

function data_type(d: Broker::Data): Broker::DataType
	{
	return __data_type(d);
	}

function refine_to_bool(d: Broker::Data): bool
	{
	return __refine_to_bool(d);
	}

function refine_to_int(d: Broker::Data): int
	{
	return __refine_to_int(d);
	}

function refine_to_count(d: Broker::Data): count
	{
	return __refine_to_count(d);
	}

function refine_to_double(d: Broker::Data): double
	{
	return __refine_to_double(d);
	}

function refine_to_string(d: Broker::Data): string
	{
	return __refine_to_string(d);
	}

function refine_to_addr(d: Broker::Data): addr
	{
	return __refine_to_addr(d);
	}

function refine_to_subnet(d: Broker::Data): subnet
	{
	return __refine_to_subnet(d);
	}

function refine_to_port(d: Broker::Data): port
	{
	return __refine_to_port(d);
	}

function refine_to_time(d: Broker::Data): time
	{
	return __refine_to_time(d);
	}

function refine_to_interval(d: Broker::Data): interval
	{
	return __refine_to_interval(d);
	}

function refine_to_enum_name(d: Broker::Data): string
	{
	return __refine_to_enum_name(d);
	}

function set_create(): Broker::Data
	{
	return __set_create();
	}

function set_clear(s: Broker::Data): bool
	{
	return __set_clear(s);
	}

function set_size(s: Broker::Data): count
	{
	return __set_size(s);
	}

function set_contains(s: Broker::Data, key: Broker::Data): bool
	{
	return __set_contains(s, key);
	}

function set_insert(s: Broker::Data, key: Broker::Data): bool
	{
	return __set_insert(s, key);
	}

function set_remove(s: Broker::Data, key: Broker::Data): bool
	{
	return __set_remove(s, key);
	}

function set_iterator(s: Broker::Data): opaque of Broker::SetIterator
	{
	return __set_iterator(s);
	}

function set_iterator_last(it: opaque of Broker::SetIterator): bool
	{
	return __set_iterator_last(it);
	}

function set_iterator_next(it: opaque of Broker::SetIterator): bool
	{
	return __set_iterator_next(it);
	}

function set_iterator_value(it: opaque of Broker::SetIterator): Broker::Data
	{
	return __set_iterator_value(it);
	}

function table_create(): Broker::Data
	{
	return __table_create();
	}

function table_clear(t: Broker::Data): bool
	{
	return __table_clear(t);
	}

function table_size(t: Broker::Data): count
	{
	return __table_size(t);
	}

function table_contains(t: Broker::Data, key: Broker::Data): bool
	{
	return __table_contains(t, key);
	}

function table_insert(t: Broker::Data, key: Broker::Data, val: Broker::Data): Broker::Data
	{
	return __table_insert(t, key, val);
	}

function table_remove(t: Broker::Data, key: Broker::Data): Broker::Data
	{
	return __table_remove(t, key);
	}

function table_lookup(t: Broker::Data, key: Broker::Data): Broker::Data
	{
	return __table_lookup(t, key);
	}

function table_iterator(t: Broker::Data): opaque of Broker::TableIterator
	{
	return __table_iterator(t);
	}

function table_iterator_last(it: opaque of Broker::TableIterator): bool
	{
	return __table_iterator_last(it);
	}

function table_iterator_next(it: opaque of Broker::TableIterator): bool
	{
	return __table_iterator_next(it);
	}

function table_iterator_value(it: opaque of Broker::TableIterator): Broker::TableItem
	{
	return __table_iterator_value(it);
	}

function vector_create(): Broker::Data
	{
	return __vector_create();
	}

function vector_clear(v: Broker::Data): bool
	{
	return __vector_clear(v);
	}

function vector_size(v: Broker::Data): count
	{
	return __vector_size(v);
	}

function vector_insert(v: Broker::Data, d: Broker::Data, idx: count): bool
	{
	return __vector_insert(v, d, idx);
	}

function vector_replace(v: Broker::Data, d: Broker::Data, idx: count): Broker::Data
	{
	return __vector_replace(v, d, idx);
	}

function vector_remove(v: Broker::Data, idx: count): Broker::Data
	{
	return __vector_remove(v, idx);
	}

function vector_lookup(v: Broker::Data, idx: count): Broker::Data
	{
	return __vector_lookup(v, idx);
	}

function vector_iterator(v: Broker::Data): opaque of Broker::VectorIterator
	{
	return __vector_iterator(v);
	}

function vector_iterator_last(it: opaque of Broker::VectorIterator): bool
	{
	return __vector_iterator_last(it);
	}

function vector_iterator_next(it: opaque of Broker::VectorIterator): bool
	{
	return __vector_iterator_next(it);
	}

function vector_iterator_value(it: opaque of Broker::VectorIterator): Broker::Data
	{
	return __vector_iterator_value(it);
	}

function record_create(sz: count): Broker::Data
	{
	return __record_create(sz);
	}

function record_size(r: Broker::Data): count
	{
	return __record_size(r);
	}

function record_assign(r: Broker::Data, d: Broker::Data, idx: count): bool
	{
	return __record_assign(r, d, idx);
	}

function record_lookup(r: Broker::Data, idx: count): Broker::Data
	{
	return __record_lookup(r, idx);
	}

function record_iterator(r: Broker::Data): opaque of Broker::RecordIterator
	{
	return __record_iterator(r);
	}

function record_iterator_last(it: opaque of Broker::RecordIterator): bool
	{
	return __record_iterator_last(it);
	}

function record_iterator_next(it: opaque of Broker::RecordIterator): bool
	{
	return __record_iterator_next(it);
	}

function record_iterator_value(it: opaque of Broker::RecordIterator): Broker::Data
	{
	return __record_iterator_value(it);
	}

@endif
