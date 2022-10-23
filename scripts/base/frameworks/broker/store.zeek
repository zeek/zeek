##! The Broker-based data store API and its various options.

@load ./main
@load base/bif/data.bif

module Broker;

export {
	## The default frequency at which clones will attempt to
	## reconnect/resynchronize with their master in the event that they become
	## disconnected.
	const default_clone_resync_interval = 10sec &redef;

	## The duration after which a clone that is disconnected from its master
	## will begin to treat its local cache as stale.  In the stale state,
	## queries to the cache will timeout.  A negative value indicates that
	## the local cache is never treated as stale.
	const default_clone_stale_interval = 5min &redef;

	## The maximum amount of time that a disconnected clone will
	## buffer data store mutation commands.  If the clone reconnects before
	## this time, it will replay all stored commands.  Note that this doesn't
	## completely prevent the loss of store updates: all mutation messages
	## are fire-and-forget and not explicitly acknowledged by the master.
	## A negative/zero value indicates to never buffer commands.
	const default_clone_mutation_buffer_interval = 2min &redef;

	## If set to true, the current node is the master node for Broker stores
	## backing Zeek tables. By default this value will be automatically set to
	## true in standalone mode, and on the manager node of a cluster. This value
	## should not typically be changed manually.
	const table_store_master = T &redef;

	## The directory used for storing persistent database files when using Broker
        ## store backed Zeek tables.
	const table_store_db_directory = "." &redef;

	## Whether a data store query could be completed or not.
	type QueryStatus: enum {
		SUCCESS,
		FAILURE,
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
	};

	## Options to tune the SQLite storage backend.
	type SQLiteOptions: record {
		## File system path of the database.
		## If left empty, will be derived from the name of the store,
		## and use the '.sqlite' file suffix.
		path: string &default = "";
	};

	## Options to tune the particular storage backends.
	type BackendOptions: record {
		sqlite: SQLiteOptions &default = SQLiteOptions();
	};

	## Create a master data store which contains key-value pairs.
	##
	## name: a unique name for the data store.
	##
	## b: the storage backend to use.
	##
	## options: tunes how some storage backends operate.
	##
	## Returns: a handle to the data store for which a subsequent call to
	##          :zeek:see:`Broker::is_closed` will return true if the store
	##          could not be created/opened.
	global create_master: function(name: string, b: BackendType &default = MEMORY,
	                               options: BackendOptions &default = BackendOptions()): opaque of Broker::Store;

	## Create a clone of a master data store which may live with a remote peer.
	## A clone automatically synchronizes to the master by
	## receiving modifications and applying them locally.  Direct modifications
	## are not possible, they must be sent through the master store, which then
	## automatically broadcasts the changes out to clones.  But queries may be
	## made directly against the local cloned copy, which may be resolved
	## quicker than reaching out to a remote master store.
	##
	## name: the unique name which identifies the master data store.
	##
	## resync_interval: the frequency at which a clone that is disconnected from
	##                  its master attempts to reconnect with it.
	##
	## stale_interval: the duration after which a clone that is disconnected
	##                 from its master will begin to treat its local cache as
	##                 stale.  In this state, queries to the clone will timeout.
	##                 A negative value indicates that the local cache is never
	##                 treated as stale.
	##
	## mutation_buffer_interval: the amount of time to buffer data store update
	##                           messages once a clone detects its master is
	##                           unavailable.  If the clone reconnects before
	##                           this time, it will replay all buffered
	##                           commands.  Note that this doesn't completely
	##                           prevent the loss of store updates: all mutation
	##                           messages are fire-and-forget and not explicitly
	##                           acknowledged by the master.  A negative/zero
	##                           value indicates that commands never buffer.
	##
	## Returns: a handle to the data store for which a subsequent call to
	##          :zeek:see:`Broker::is_closed` will return true if the store
	##          could not be created/opened.
	global create_clone: function(name: string,
	                              resync_interval: interval &default = default_clone_resync_interval,
	                              stale_interval: interval &default = default_clone_stale_interval,
	                              mutation_buffer_interval: interval &default = default_clone_mutation_buffer_interval): opaque of Broker::Store;

	## Close a data store.
	##
	## h: a data store handle.
	##
	## Returns: true if store was valid and is now closed.  The handle can no
	##          longer be used for data store operations.
	global close: function(h: opaque of Broker::Store): bool;

	## Check if a store is closed or not.
	##
	## Returns: true if the store is closed.
	global is_closed: function(h: opaque of Broker::Store): bool;

	## Get the name of a store.
	##
	## Returns: the name of the store.
	global store_name: function(h: opaque of Broker::Store): string;

	## Check if a key exists in a data store.
	##
	## h: the handle of the store to query.
	##
	## k: the key to lookup.
	##
	## Returns: True if the key exists in the data store.
	global exists: function(h: opaque of Broker::Store, k: any): QueryResult;

	## Lookup the value associated with a key in a data store.
	##
	## h: the handle of the store to query.
	##
	## k: the key to lookup.
	##
	## Returns: the result of the query.
	global get: function(h: opaque of Broker::Store, k: any): QueryResult;

	## Insert a key-value pair into the store, but only if the key does not
	## already exist.
	##
	## h: the handle of the store to modify.
	##
	## k: the key to insert.
	##
	## v: the value to insert.
	##
	## e: the expiration interval of the key-value pair.
	##
	## Returns: the result of the query which is a boolean data value that is
	##          true if the insertion happened, or false if it was rejected
	##          due to the key already existing.
	global put_unique: function(h: opaque of Broker::Store,
	                            k: any, v: any, e: interval &default=0sec): QueryResult;

	## Retrieve a specific index from an existing container value. This
	## is supported for values of types set, table, and vector.
	##
	## h: the handle of the store to query.
	##
	## k: the key of the container value to lookup.
	##
	## i: the index to retrieve from the container value.
	##
	## Returns: For tables and vectors, the value at the given index, or
	##          failure if the index doesn't exist. For sets, a boolean
	##          indicating whether the index exists. Returns failure if the key
	##          does not exist at all.
	global get_index_from_value: function(h: opaque of Broker::Store,
	                                      k: any, i: any): QueryResult;

	## Insert a key-value pair into the store.
	##
	## h: the handle of the store to modify.
	##
	## k: the key to insert.
	##
	## v: the value to insert.
	##
	## e: the expiration interval of the key-value pair.
	##
	## Returns: false if the store handle was not valid.
	global put: function(h: opaque of Broker::Store,
	                     k: any, v: any, e: interval &default=0sec) : bool;

	## Remove a key-value pair from the store.
	##
	## h: the handle of the store to modify.
	##
	## k: the key to remove.
	##
	## Returns: false if the store handle was not valid.
	global erase: function(h: opaque of Broker::Store, k: any) : bool;

	## Increments an existing value by a given amount. This is supported for all
	## numerical types, as well as for timestamps.
	##
	## h: the handle of the store to modify.
	##
	## k: the key whose associated value is to be modified. The key must
	##    already exist.
	##
	## a: the amount to increment the value by.
	##
	## e: the new expiration interval of the modified key. If null, the
	##    current expiration time isn't changed.
	##
	## Returns: false if the store handle was not valid.
	global increment: function(h: opaque of Broker::Store, k: any,
	                           a: any &default = 1,
	                           e: interval &default=0sec) : bool;

	## Decrements an existing value by a given amount. This is supported for all
	## numerical types, as well as for timestamps.
	##
	## h: the handle of the store to modify.
	##
	## k: the key whose associated value is to be modified. The key must
	##    already exist.
	##
	## amount: the amount to decrement the value by.
	##
	## e: the new expiration interval of the modified key. If null, the current
	##    expiration time isn't changed.
	##
	## Returns: false if the store handle was not valid.
	global decrement: function(h: opaque of Broker::Store, k: any,
	                           a: any &default = 1,
	                           e: interval &default=0sec) : bool;

	## Extends an existing string with another.
	##
	## h: the handle of the store to modify.
	##
	## k: the key whose associated value is to be modified. The key must
	##    already exist.
	##
	## s: the string to append.
	##
	## e: the new expiration interval of the modified key. If null, the
	##    current expiration time isn't changed.
	##
	## Returns: false if the store handle was not valid.
	global append: function(h: opaque of Broker::Store, k: any, s: string,
	                        e: interval &default=0sec) : bool;

	## Inserts an element into an existing set.
	##
	## h: the handle of the store to modify.
	##
	## k: the key whose associated value is to be modified. The key must
	##    already exist.
	##
	## i: the index to insert into the set.
	##
	## e: the new expiration interval of the modified key. If null, the
	##    current expiration time isn't changed.
	##
	## Returns: false if the store handle was not valid.
	global insert_into_set: function(h: opaque of Broker::Store,
	                                 k: any, i: any,
	                                 e: interval &default=0sec) : bool;

	## Inserts an element into an existing table.
	##
	## h: the handle of the store to modify.
	##
	## k: the key whose associated value is to be modified. The key must
	##    already exist.
	##
	## i: the index to insert into the table
	##
	## v: the value to associate with the index.
	##
	## e: the new expiration interval of the modified key. If null, the
	##    current expiration time isn't changed.
	##
	## Returns: false if the store handle was not valid.
	global insert_into_table: function(h: opaque of Broker::Store,
	                                   k: any, i: any, v: any,
	                                   e: interval &default=0sec) : bool;

	## Removes an element from an existing set or table.
	##
	## h: the handle of the store to modify.
	##
	## k: the key whose associated value is to be modified. The key must
	##    already exist.
	##
	## i: the index to remove from the set or table.
	##
	## e: the new expiration interval of the modified key. If null, the
	##    current expiration time isn't changed.
	##
	## Returns: false if the store handle was not valid.
	global remove_from: function(h: opaque of Broker::Store,
	                             k: any, i: any,
	                             e: interval &default=0sec) : bool;

	## Appends an element to an existing vector.
	##
	## h: the handle of the store to modify.
	##
	## k: the key whose associated value is to be modified. The key must
	##    already exist.
	##
	## b: the value to append to the vector.
	##
	## e: the new expiration interval of the modified key. If null, the
	##    current expiration time isn't changed.
	##
	## Returns: false if the store handle was not valid.
	global push: function(h: opaque of Broker::Store,
	                      k: any, v: any,
	                      e: interval &default=0sec) : bool;

	## Removes the last element of an existing vector.
	##
	## h: the handle of the store to modify.
	##
	## k: the key whose associated value is to be modified. The key must
	##    already exist.
	##
	## e: the new expiration interval of the modified key. If null, the
	##    current expiration time isn't changed.
	##
	## Returns: false if the store handle was not valid.
	global pop: function(h: opaque of Broker::Store,
	                     k: any,
	                     e: interval &default=0sec) : bool;

	## Returns a set with all of a store's keys. The results reflect a snapshot
	## in time that may diverge from reality soon afterwards.   When accessing
	## any of the element, it may no longer actually be there. The function is
	## also expensive for large stores, as it copies the complete set.
	##
	## Returns: a set with the keys.  If you expect the keys to be of
	##          non-uniform type, consider using
	##          :zeek:see:`Broker::set_iterator` to iterate over the result.
	global keys: function(h: opaque of Broker::Store): QueryResult;

	## Deletes all of a store's content, it will be empty afterwards.
	##
	## Returns: false if the store handle was not valid.
	global clear: function(h: opaque of Broker::Store) : bool;

	##########################
	# Data API               #
	##########################

	## Convert any Zeek value to communication data.
	##
	## .. note:: Normally you won't need to use this function as data
	##    conversion happens implicitly when passing Zeek values into Broker
	##    functions.
	##
	## d: any Zeek value to attempt to convert (not all types are supported).
	##
	## Returns: the converted communication data.  If the supplied Zeek data
	##          type does not support conversion to communication data, the
	##          returned record's optional field will not be set.
	global data: function(d: any): Broker::Data;

	## Retrieve the type of data associated with communication data.
	##
	## d: the communication data.
	##
	## Returns: The data type associated with the communication data.
	##          Note that Broker represents records in the same way as
	##          vectors, so there is no "record" type.
	global data_type: function(d: Broker::Data): Broker::DataType;

	## Create communication data of type "set".
	global set_create: function(): Broker::Data;

	## Remove all elements within a set.
	##
	## s: the set to clear.
	##
	## Returns: always true.
	global set_clear: function(s: Broker::Data) : bool;

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
	global set_contains: function(s: Broker::Data, key: any) : bool;

	## Insert an element into a set.
	##
	## s: the set to modify.
	##
	## key: the element to insert.
	##
	## Returns: true if the key was inserted, or false if it already existed.
	global set_insert: function(s: Broker::Data, key: any) : bool;

	## Remove an element from a set.
	##
	## s: the set to modify.
	##
	## key: the element to remove.
	##
	## Returns: true if the element existed in the set and is now removed.
	global set_remove: function(s: Broker::Data, key: any) : bool;

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
	global set_iterator_last: function(it: opaque of Broker::SetIterator) : bool;

	## Advance an iterator.
	##
	## it: an iterator.
	##
	## Returns: true if the iterator, after advancing, still references an element
	##          in the collection.  False if the iterator, after advancing, is
	##          one-past-the-final-element.
	global set_iterator_next: function(it: opaque of Broker::SetIterator) : bool;

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
	global table_clear: function(t: Broker::Data) : bool;

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
	global table_contains: function(t: Broker::Data, key: any) : bool;

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
	global table_insert: function(t: Broker::Data, key: any, val: any): Broker::Data;

	## Remove a key-value pair from a table.
	##
	## t: the table to modify.
	##
	## key: the key to remove from the table.
	##
	## Returns: the value associated with the key.  If the key did not exist, then
	##          the optional field of the returned record is not set.
	global table_remove: function(t: Broker::Data, key: any): Broker::Data;

	## Retrieve a value from a table.
	##
	## t: the table to query.
	##
	## key: the key to lookup.
	##
	## Returns: the value associated with the key.  If the key did not exist, then
	##          the optional field of the returned record is not set.
	global table_lookup: function(t: Broker::Data, key: any): Broker::Data;

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
	global table_iterator_last: function(it: opaque of Broker::TableIterator) : bool;

	## Advance an iterator.
	##
	## it: an iterator.
	##
	## Returns: true if the iterator, after advancing, still references an element
	##          in the collection.  False if the iterator, after advancing, is
	##          one-past-the-final-element.
	global table_iterator_next: function(it: opaque of Broker::TableIterator) : bool;

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
	global vector_clear: function(v: Broker::Data) : bool;

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
	global vector_insert: function(v: Broker::Data, idx: count, d: any) : bool;

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
	global vector_replace: function(v: Broker::Data, idx: count, d: any): Broker::Data;

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
	global vector_iterator_last: function(it: opaque of Broker::VectorIterator) : bool;

	## Advance an iterator.
	##
	## it: an iterator.
	##
	## Returns: true if the iterator, after advancing, still references an element
	##          in the collection.  False if the iterator, after advancing, is
	##          one-past-the-final-element.
	global vector_iterator_next: function(it: opaque of Broker::VectorIterator) : bool;

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
	global record_assign: function(r: Broker::Data, idx: count, d: any) : bool;

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
	global record_iterator_last: function(it: opaque of Broker::RecordIterator) : bool;

	## Advance an iterator.
	##
	## it: an iterator.
	##
	## Returns: true if the iterator, after advancing, still references an element
	##          in the collection.  False if the iterator, after advancing, is
	##          one-past-the-final-element.
	global record_iterator_next: function(it: opaque of Broker::RecordIterator) : bool;

	## Retrieve the data at an iterator's current position.
	##
	## it: an iterator.
	##
	## Returns: element in the collection that the iterator currently references.
	global record_iterator_value: function(it: opaque of Broker::RecordIterator): Broker::Data;
}

@load base/bif/store.bif

module Broker;

function create_master(name: string, b: BackendType &default = MEMORY,
                       options: BackendOptions &default = BackendOptions()): opaque of Broker::Store
	{
	return __create_master(name, b, options);
	}

function create_clone(name: string,
                      resync_interval: interval &default = default_clone_resync_interval,
                      stale_interval: interval &default = default_clone_stale_interval,
                      mutation_buffer_interval: interval &default = default_clone_mutation_buffer_interval): opaque of Broker::Store
	{
	return __create_clone(name, resync_interval, stale_interval,
	                      mutation_buffer_interval);
	}

function close(h: opaque of Broker::Store): bool
	{
	return __close(h);
	}

function is_closed(h: opaque of Broker::Store): bool
	{
	return __is_closed(h);
	}

function store_name(h: opaque of Broker::Store): string
	{
	return __store_name(h);
	}

function exists(h: opaque of Broker::Store, k: any): QueryResult
	{
	return __exists(h, k);
	}

function get(h: opaque of Broker::Store, k: any): QueryResult
	{
	return __get(h, k);
	}

function put_unique(h: opaque of Broker::Store, k: any, v: any,
             e: interval &default=0sec): QueryResult
    {
    return __put_unique(h, k, v, e);
    }

function get_index_from_value(h: opaque of Broker::Store, k: any, i: any): QueryResult
	{
	return __get_index_from_value(h, k, i);
	}

function keys(h: opaque of Broker::Store): QueryResult
	{
	return __keys(h);
	}

function put(h: opaque of Broker::Store, k: any, v: any, e: interval) : bool
	{
	return __put(h, k, v, e);
	}

function erase(h: opaque of Broker::Store, k: any) : bool
	{
	return __erase(h, k);
	}

function increment(h: opaque of Broker::Store, k: any, a: any, e: interval) : bool
	{
	return __increment(h, k, a, e);
	}

function decrement(h: opaque of Broker::Store, k: any, a: any, e: interval) : bool
	{
	return __decrement(h, k, a, e);
	}

function append(h: opaque of Broker::Store, k: any, s: string, e: interval) : bool
	{
	return __append(h, k, s, e);
	}

function insert_into_set(h: opaque of Broker::Store, k: any, i: any, e: interval) : bool
	{
	return __insert_into_set(h, k, i, e);
	}

function insert_into_table(h: opaque of Broker::Store, k: any, i: any, v: any, e: interval) : bool
	{
	return __insert_into_table(h, k, i, v, e);
	}

function remove_from(h: opaque of Broker::Store, k: any, i: any, e: interval) : bool
	{
	return __remove_from(h, k, i, e);
	}

function push(h: opaque of Broker::Store, k: any, v: any, e: interval) : bool
	{
	return __push(h, k, v, e);
	}

function pop(h: opaque of Broker::Store, k: any, e: interval) : bool
	{
	return __pop(h, k, e);
	}

function clear(h: opaque of Broker::Store) : bool
	{
	return __clear(h);
	}

function data_type(d: Broker::Data): Broker::DataType
	{
	return __data_type(d);
	}

function data(d: any): Broker::Data
	{
	return __data(d);
	}

function set_create(): Broker::Data
	{
	return __set_create();
	}

function set_clear(s: Broker::Data) : bool
	{
	return __set_clear(s);
	}

function set_size(s: Broker::Data): count
	{
	return __set_size(s);
	}

function set_contains(s: Broker::Data, key: any) : bool
	{
	return __set_contains(s, key);
	}

function set_insert(s: Broker::Data, key: any) : bool
	{
	return __set_insert(s, key);
	}

function set_remove(s: Broker::Data, key: any) : bool
	{
	return __set_remove(s, key);
	}

function set_iterator(s: Broker::Data): opaque of Broker::SetIterator
	{
	return __set_iterator(s);
	}

function set_iterator_last(it: opaque of Broker::SetIterator) : bool
	{
	return __set_iterator_last(it);
	}

function set_iterator_next(it: opaque of Broker::SetIterator) : bool
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

function table_clear(t: Broker::Data) : bool
	{
	return __table_clear(t);
	}

function table_size(t: Broker::Data): count
	{
	return __table_size(t);
	}

function table_contains(t: Broker::Data, key: any) : bool
	{
	return __table_contains(t, key);
	}

function table_insert(t: Broker::Data, key: any, val: any): Broker::Data
	{
	return __table_insert(t, key, val);
	}

function table_remove(t: Broker::Data, key: any): Broker::Data
	{
	return __table_remove(t, key);
	}

function table_lookup(t: Broker::Data, key: any): Broker::Data
	{
	return __table_lookup(t, key);
	}

function table_iterator(t: Broker::Data): opaque of Broker::TableIterator
	{
	return __table_iterator(t);
	}

function table_iterator_last(it: opaque of Broker::TableIterator) : bool
	{
	return __table_iterator_last(it);
	}

function table_iterator_next(it: opaque of Broker::TableIterator) : bool
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

function vector_clear(v: Broker::Data) : bool
	{
	return __vector_clear(v);
	}

function vector_size(v: Broker::Data): count
	{
	return __vector_size(v);
	}

function vector_insert(v: Broker::Data, idx: count, d: any) : bool
	{
	return __vector_insert(v, idx, d);
	}

function vector_replace(v: Broker::Data, idx: count, d: any): Broker::Data
	{
	return __vector_replace(v, idx, d);
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

function vector_iterator_last(it: opaque of Broker::VectorIterator) : bool
	{
	return __vector_iterator_last(it);
	}

function vector_iterator_next(it: opaque of Broker::VectorIterator) : bool
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

function record_assign(r: Broker::Data, idx: count, d: any) : bool
	{
	return __record_assign(r, idx, d);
	}

function record_lookup(r: Broker::Data, idx: count): Broker::Data
	{
	return __record_lookup(r, idx);
	}

function record_iterator(r: Broker::Data): opaque of Broker::RecordIterator
	{
	return __record_iterator(r);
	}

function record_iterator_last(it: opaque of Broker::RecordIterator) : bool
	{
	return __record_iterator_last(it);
	}

function record_iterator_next(it: opaque of Broker::RecordIterator) : bool
	{
	return __record_iterator_next(it);
	}

function record_iterator_value(it: opaque of Broker::RecordIterator): Broker::Data
	{
	return __record_iterator_value(it);
	}

