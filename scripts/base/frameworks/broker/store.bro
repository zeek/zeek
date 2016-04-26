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

}

@load base/bif/store.bif

module Broker;

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

