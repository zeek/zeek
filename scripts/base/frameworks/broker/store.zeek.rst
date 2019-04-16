:tocdepth: 3

base/frameworks/broker/store.zeek
=================================
.. bro:namespace:: Broker

The Broker-based data store API and its various options.

:Namespace: Broker
:Imports: :doc:`base/bif/data.bif.zeek </scripts/base/bif/data.bif.zeek>`, :doc:`base/bif/store.bif.zeek </scripts/base/bif/store.bif.zeek>`, :doc:`base/frameworks/broker/main.zeek </scripts/base/frameworks/broker/main.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
================================================================================================= =======================================================================
:bro:id:`Broker::default_clone_mutation_buffer_interval`: :bro:type:`interval` :bro:attr:`&redef` The maximum amount of time that a disconnected clone will
                                                                                                  buffer data store mutation commands.
:bro:id:`Broker::default_clone_resync_interval`: :bro:type:`interval` :bro:attr:`&redef`          The default frequency at which clones will attempt to
                                                                                                  reconnect/resynchronize with their master in the event that they become
                                                                                                  disconnected.
:bro:id:`Broker::default_clone_stale_interval`: :bro:type:`interval` :bro:attr:`&redef`           The duration after which a clone that is disconnected from its master
                                                                                                  will begin to treat its local cache as stale.
================================================================================================= =======================================================================

Types
#####
====================================================== =====================================================
:bro:type:`Broker::BackendOptions`: :bro:type:`record` Options to tune the particular storage backends.
:bro:type:`Broker::BackendType`: :bro:type:`enum`      Enumerates the possible storage backends.
:bro:type:`Broker::QueryResult`: :bro:type:`record`    The result of a data store query.
:bro:type:`Broker::QueryStatus`: :bro:type:`enum`      Whether a data store query could be completed or not.
:bro:type:`Broker::RocksDBOptions`: :bro:type:`record` Options to tune the RocksDB storage backend.
:bro:type:`Broker::SQLiteOptions`: :bro:type:`record`  Options to tune the SQLite storage backend.
====================================================== =====================================================

Functions
#########
============================================================= =============================================================================
:bro:id:`Broker::append`: :bro:type:`function`                Extends an existing string with another.
:bro:id:`Broker::clear`: :bro:type:`function`                 Deletes all of a store's content, it will be empty afterwards.
:bro:id:`Broker::close`: :bro:type:`function`                 Close a data store.
:bro:id:`Broker::create_clone`: :bro:type:`function`          Create a clone of a master data store which may live with a remote peer.
:bro:id:`Broker::create_master`: :bro:type:`function`         Create a master data store which contains key-value pairs.
:bro:id:`Broker::data`: :bro:type:`function`                  Convert any Bro value to communication data.
:bro:id:`Broker::data_type`: :bro:type:`function`             Retrieve the type of data associated with communication data.
:bro:id:`Broker::decrement`: :bro:type:`function`             Decrements an existing value by a given amount.
:bro:id:`Broker::erase`: :bro:type:`function`                 Remove a key-value pair from the store.
:bro:id:`Broker::exists`: :bro:type:`function`                Check if a key exists in a data store.
:bro:id:`Broker::get`: :bro:type:`function`                   Lookup the value associated with a key in a data store.
:bro:id:`Broker::get_index_from_value`: :bro:type:`function`  Retrieve a specific index from an existing container value.
:bro:id:`Broker::increment`: :bro:type:`function`             Increments an existing value by a given amount.
:bro:id:`Broker::insert_into_set`: :bro:type:`function`       Inserts an element into an existing set.
:bro:id:`Broker::insert_into_table`: :bro:type:`function`     Inserts an element into an existing table.
:bro:id:`Broker::is_closed`: :bro:type:`function`             Check if a store is closed or not.
:bro:id:`Broker::keys`: :bro:type:`function`                  Returns a set with all of a store's keys.
:bro:id:`Broker::pop`: :bro:type:`function`                   Removes the last element of an existing vector.
:bro:id:`Broker::push`: :bro:type:`function`                  Appends an element to an existing vector.
:bro:id:`Broker::put`: :bro:type:`function`                   Insert a key-value pair in to the store.
:bro:id:`Broker::put_unique`: :bro:type:`function`            Insert a key-value pair in to the store, but only if the key does not
                                                              already exist.
:bro:id:`Broker::record_assign`: :bro:type:`function`         Replace a field in a record at a particular position.
:bro:id:`Broker::record_create`: :bro:type:`function`         Create communication data of type "record".
:bro:id:`Broker::record_iterator`: :bro:type:`function`       Create an iterator for a record.
:bro:id:`Broker::record_iterator_last`: :bro:type:`function`  Check if there are no more elements to iterate over.
:bro:id:`Broker::record_iterator_next`: :bro:type:`function`  Advance an iterator.
:bro:id:`Broker::record_iterator_value`: :bro:type:`function` Retrieve the data at an iterator's current position.
:bro:id:`Broker::record_lookup`: :bro:type:`function`         Lookup a field in a record at a particular position.
:bro:id:`Broker::record_size`: :bro:type:`function`           Get the number of fields within a record.
:bro:id:`Broker::remove_from`: :bro:type:`function`           Removes an element from an existing set or table.
:bro:id:`Broker::set_clear`: :bro:type:`function`             Remove all elements within a set.
:bro:id:`Broker::set_contains`: :bro:type:`function`          Check if a set contains a particular element.
:bro:id:`Broker::set_create`: :bro:type:`function`            Create communication data of type "set".
:bro:id:`Broker::set_insert`: :bro:type:`function`            Insert an element into a set.
:bro:id:`Broker::set_iterator`: :bro:type:`function`          Create an iterator for a set.
:bro:id:`Broker::set_iterator_last`: :bro:type:`function`     Check if there are no more elements to iterate over.
:bro:id:`Broker::set_iterator_next`: :bro:type:`function`     Advance an iterator.
:bro:id:`Broker::set_iterator_value`: :bro:type:`function`    Retrieve the data at an iterator's current position.
:bro:id:`Broker::set_remove`: :bro:type:`function`            Remove an element from a set.
:bro:id:`Broker::set_size`: :bro:type:`function`              Get the number of elements within a set.
:bro:id:`Broker::store_name`: :bro:type:`function`            Get the name of a store.
:bro:id:`Broker::table_clear`: :bro:type:`function`           Remove all elements within a table.
:bro:id:`Broker::table_contains`: :bro:type:`function`        Check if a table contains a particular key.
:bro:id:`Broker::table_create`: :bro:type:`function`          Create communication data of type "table".
:bro:id:`Broker::table_insert`: :bro:type:`function`          Insert a key-value pair into a table.
:bro:id:`Broker::table_iterator`: :bro:type:`function`        Create an iterator for a table.
:bro:id:`Broker::table_iterator_last`: :bro:type:`function`   Check if there are no more elements to iterate over.
:bro:id:`Broker::table_iterator_next`: :bro:type:`function`   Advance an iterator.
:bro:id:`Broker::table_iterator_value`: :bro:type:`function`  Retrieve the data at an iterator's current position.
:bro:id:`Broker::table_lookup`: :bro:type:`function`          Retrieve a value from a table.
:bro:id:`Broker::table_remove`: :bro:type:`function`          Remove a key-value pair from a table.
:bro:id:`Broker::table_size`: :bro:type:`function`            Get the number of elements within a table.
:bro:id:`Broker::vector_clear`: :bro:type:`function`          Remove all elements within a vector.
:bro:id:`Broker::vector_create`: :bro:type:`function`         Create communication data of type "vector".
:bro:id:`Broker::vector_insert`: :bro:type:`function`         Insert an element into a vector at a particular position, possibly displacing
                                                              existing elements (insertion always grows the size of the vector by one).
:bro:id:`Broker::vector_iterator`: :bro:type:`function`       Create an iterator for a vector.
:bro:id:`Broker::vector_iterator_last`: :bro:type:`function`  Check if there are no more elements to iterate over.
:bro:id:`Broker::vector_iterator_next`: :bro:type:`function`  Advance an iterator.
:bro:id:`Broker::vector_iterator_value`: :bro:type:`function` Retrieve the data at an iterator's current position.
:bro:id:`Broker::vector_lookup`: :bro:type:`function`         Lookup an element in a vector at a particular position.
:bro:id:`Broker::vector_remove`: :bro:type:`function`         Remove an element from a vector at a particular position.
:bro:id:`Broker::vector_replace`: :bro:type:`function`        Replace an element in a vector at a particular position.
:bro:id:`Broker::vector_size`: :bro:type:`function`           Get the number of elements within a vector.
============================================================= =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Broker::default_clone_mutation_buffer_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``2.0 mins``

   The maximum amount of time that a disconnected clone will
   buffer data store mutation commands.  If the clone reconnects before
   this time, it will replay all stored commands.  Note that this doesn't
   completely prevent the loss of store updates: all mutation messages
   are fire-and-forget and not explicitly acknowledged by the master.
   A negative/zero value indicates to never buffer commands.

.. bro:id:: Broker::default_clone_resync_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10.0 secs``

   The default frequency at which clones will attempt to
   reconnect/resynchronize with their master in the event that they become
   disconnected.

.. bro:id:: Broker::default_clone_stale_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5.0 mins``

   The duration after which a clone that is disconnected from its master
   will begin to treat its local cache as stale.  In the stale state,
   queries to the cache will timeout.  A negative value indicates that
   the local cache is never treated as stale.

Types
#####
.. bro:type:: Broker::BackendOptions

   :Type: :bro:type:`record`

      sqlite: :bro:type:`Broker::SQLiteOptions` :bro:attr:`&default` = ``[path=]`` :bro:attr:`&optional`

      rocksdb: :bro:type:`Broker::RocksDBOptions` :bro:attr:`&default` = ``[path=]`` :bro:attr:`&optional`

   Options to tune the particular storage backends.

.. bro:type:: Broker::BackendType

   :Type: :bro:type:`enum`

      .. bro:enum:: Broker::MEMORY Broker::BackendType

      .. bro:enum:: Broker::SQLITE Broker::BackendType

      .. bro:enum:: Broker::ROCKSDB Broker::BackendType

   Enumerates the possible storage backends.

.. bro:type:: Broker::QueryResult

   :Type: :bro:type:`record`

      status: :bro:type:`Broker::QueryStatus`
         Whether the query completed or not.

      result: :bro:type:`Broker::Data`
         The result of the query.  Certain queries may use a particular
         data type (e.g. querying store size always returns a count, but
         a lookup may return various data types).

   The result of a data store query.

.. bro:type:: Broker::QueryStatus

   :Type: :bro:type:`enum`

      .. bro:enum:: Broker::SUCCESS Broker::QueryStatus

      .. bro:enum:: Broker::FAILURE Broker::QueryStatus

   Whether a data store query could be completed or not.

.. bro:type:: Broker::RocksDBOptions

   :Type: :bro:type:`record`

      path: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`
         File system path of the database.
         If left empty, will be derived from the name of the store,
         and use the '.rocksdb' file suffix.

   Options to tune the RocksDB storage backend.

.. bro:type:: Broker::SQLiteOptions

   :Type: :bro:type:`record`

      path: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`
         File system path of the database.
         If left empty, will be derived from the name of the store,
         and use the '.sqlite' file suffix.

   Options to tune the SQLite storage backend.

Functions
#########
.. bro:id:: Broker::append

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, s: :bro:type:`string`, e: :bro:type:`interval` :bro:attr:`&default` = ``0 secs`` :bro:attr:`&optional`) : :bro:type:`bool`

   Extends an existing string with another.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :s: the string to append.
   

   :e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. bro:id:: Broker::clear

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store) : :bro:type:`bool`

   Deletes all of a store's content, it will be empty afterwards.
   

   :returns: false if the store handle was not valid.

.. bro:id:: Broker::close

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store) : :bro:type:`bool`

   Close a data store.
   

   :h: a data store handle.
   

   :returns: true if store was valid and is now closed.  The handle can no
            longer be used for data store operations.

.. bro:id:: Broker::create_clone

   :Type: :bro:type:`function` (name: :bro:type:`string`, resync_interval: :bro:type:`interval` :bro:attr:`&default` = :bro:see:`Broker::default_clone_resync_interval` :bro:attr:`&optional`, stale_interval: :bro:type:`interval` :bro:attr:`&default` = :bro:see:`Broker::default_clone_stale_interval` :bro:attr:`&optional`, mutation_buffer_interval: :bro:type:`interval` :bro:attr:`&default` = :bro:see:`Broker::default_clone_mutation_buffer_interval` :bro:attr:`&optional`) : :bro:type:`opaque` of Broker::Store

   Create a clone of a master data store which may live with a remote peer.
   A clone automatically synchronizes to the master by
   receiving modifications and applying them locally.  Direct modifications
   are not possible, they must be sent through the master store, which then
   automatically broadcasts the changes out to clones.  But queries may be
   made directly against the local cloned copy, which may be resolved
   quicker than reaching out to a remote master store.
   

   :name: the unique name which identifies the master data store.
   

   :resync_interval: the frequency at which a clone that is disconnected from
                    its master attempts to reconnect with it.
   

   :stale_interval: the duration after which a clone that is disconnected
                   from its master will begin to treat its local cache as
                   stale.  In this state, queries to the clone will timeout.
                   A negative value indicates that the local cache is never
                   treated as stale.
   

   :mutation_buffer_interval: the amount of time to buffer data store update
                             messages once a clone detects its master is
                             unavailable.  If the clone reconnects before
                             this time, it will replay all buffered
                             commands.  Note that this doesn't completely
                             prevent the loss of store updates: all mutation
                             messages are fire-and-forget and not explicitly
                             acknowledged by the master.  A negative/zero
                             value indicates that commands never buffer.
   

   :returns: a handle to the data store.

.. bro:id:: Broker::create_master

   :Type: :bro:type:`function` (name: :bro:type:`string`, b: :bro:type:`Broker::BackendType` :bro:attr:`&default` = ``Broker::MEMORY`` :bro:attr:`&optional`, options: :bro:type:`Broker::BackendOptions` :bro:attr:`&default` = ``[sqlite=[path=], rocksdb=[path=]]`` :bro:attr:`&optional`) : :bro:type:`opaque` of Broker::Store

   Create a master data store which contains key-value pairs.
   

   :name: a unique name for the data store.
   

   :b: the storage backend to use.
   

   :options: tunes how some storage backends operate.
   

   :returns: a handle to the data store.

.. bro:id:: Broker::data

   :Type: :bro:type:`function` (d: :bro:type:`any`) : :bro:type:`Broker::Data`

   Convert any Bro value to communication data.
   
   .. note:: Normally you won't need to use this function as data
      conversion happens implicitly when passing Bro values into Broker
      functions.
   

   :d: any Bro value to attempt to convert (not all types are supported).
   

   :returns: the converted communication data.  If the supplied Bro data
            type does not support conversion to communication data, the
            returned record's optional field will not be set.

.. bro:id:: Broker::data_type

   :Type: :bro:type:`function` (d: :bro:type:`Broker::Data`) : :bro:type:`Broker::DataType`

   Retrieve the type of data associated with communication data.
   

   :d: the communication data.
   

   :returns: The data type associated with the communication data.
            Note that broker represents records in the same way as
            vectors, so there is no "record" type.

.. bro:id:: Broker::decrement

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, a: :bro:type:`any` :bro:attr:`&default` = ``1`` :bro:attr:`&optional`, e: :bro:type:`interval` :bro:attr:`&default` = ``0 secs`` :bro:attr:`&optional`) : :bro:type:`bool`

   Decrements an existing value by a given amount. This is supported for all
   numerical types, as well as for timestamps.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :amount: the amount to decrement the value by. 
   

   :e: the new expiration interval of the modified key. If null, the current
      expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. bro:id:: Broker::erase

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`) : :bro:type:`bool`

   Remove a key-value pair from the store.
   

   :h: the handle of the store to modify.
   

   :k: the key to remove.
   

   :returns: false if the store handle was not valid.

.. bro:id:: Broker::exists

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`) : :bro:type:`Broker::QueryResult`

   Check if a key exists in a data store.
   

   :h: the handle of the store to query.
   

   :k: the key to lookup.
   

   :returns: True if the key exists in the data store.

.. bro:id:: Broker::get

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`) : :bro:type:`Broker::QueryResult`

   Lookup the value associated with a key in a data store.
   

   :h: the handle of the store to query.
   

   :k: the key to lookup.
   

   :returns: the result of the query.

.. bro:id:: Broker::get_index_from_value

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, i: :bro:type:`any`) : :bro:type:`Broker::QueryResult`

   Retrieve a specific index from an existing container value. This
   is supported for values of types set, table, and vector.
   

   :h: the handle of the store to query.
   

   :k: the key of the container value to lookup.
   

   :i: the index to retrieve from the container value.
   

   :returns: For tables and vectors, the value at the given index, or
            failure if the index doesn't exist. For sets, a boolean
            indicating whether the index exists. Returns failure if the key
            does not exist at all.

.. bro:id:: Broker::increment

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, a: :bro:type:`any` :bro:attr:`&default` = ``1`` :bro:attr:`&optional`, e: :bro:type:`interval` :bro:attr:`&default` = ``0 secs`` :bro:attr:`&optional`) : :bro:type:`bool`

   Increments an existing value by a given amount. This is supported for all
   numerical types, as well as for timestamps.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :a: the amount to increment the value by. 
   

   :e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. bro:id:: Broker::insert_into_set

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, i: :bro:type:`any`, e: :bro:type:`interval` :bro:attr:`&default` = ``0 secs`` :bro:attr:`&optional`) : :bro:type:`bool`

   Inserts an element into an existing set.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :i: the index to insert into the set.
   

   :e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. bro:id:: Broker::insert_into_table

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, i: :bro:type:`any`, v: :bro:type:`any`, e: :bro:type:`interval` :bro:attr:`&default` = ``0 secs`` :bro:attr:`&optional`) : :bro:type:`bool`

   Inserts an element into an existing table.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :i: the index to insert into the table
   

   :v: the value to associate with the index.
   

   :e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. bro:id:: Broker::is_closed

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store) : :bro:type:`bool`

   Check if a store is closed or not.
   

   :returns: true if the store is closed.

.. bro:id:: Broker::keys

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store) : :bro:type:`Broker::QueryResult`

   Returns a set with all of a store's keys. The results reflect a snapshot
   in time that may diverge from reality soon afterwards.   When acessing
   any of the element, it may no longer actually be there. The function is
   also expensive for large stores, as it copies the complete set.
   

   :returns: a set with the keys.  If you expect the keys to be of
            non-uniform type, consider using
            :bro:see:`Broker::set_iterator` to iterate over the result.

.. bro:id:: Broker::pop

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, e: :bro:type:`interval` :bro:attr:`&default` = ``0 secs`` :bro:attr:`&optional`) : :bro:type:`bool`

   Removes the last element of an existing vector.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. bro:id:: Broker::push

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, v: :bro:type:`any`, e: :bro:type:`interval` :bro:attr:`&default` = ``0 secs`` :bro:attr:`&optional`) : :bro:type:`bool`

   Appends an element to an existing vector.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :b: the value to append to the vector.
   

   :e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. bro:id:: Broker::put

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, v: :bro:type:`any`, e: :bro:type:`interval` :bro:attr:`&default` = ``0 secs`` :bro:attr:`&optional`) : :bro:type:`bool`

   Insert a key-value pair in to the store.
   

   :h: the handle of the store to modify.
   

   :k: the key to insert.
   

   :v: the value to insert.
   

   :e: the expiration interval of the key-value pair.
   

   :returns: false if the store handle was not valid.

.. bro:id:: Broker::put_unique

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, v: :bro:type:`any`, e: :bro:type:`interval` :bro:attr:`&default` = ``0 secs`` :bro:attr:`&optional`) : :bro:type:`Broker::QueryResult`

   Insert a key-value pair in to the store, but only if the key does not
   already exist.
   

   :h: the handle of the store to modify.
   

   :k: the key to insert.
   

   :v: the value to insert.
   

   :e: the expiration interval of the key-value pair.
   

   :returns: the result of the query which is a boolean data value that is
            true if the insertion happened, or false if it was rejected
            due to the key already existing.

.. bro:id:: Broker::record_assign

   :Type: :bro:type:`function` (r: :bro:type:`Broker::Data`, idx: :bro:type:`count`, d: :bro:type:`any`) : :bro:type:`bool`

   Replace a field in a record at a particular position.
   

   :r: the record to modify.
   

   :d: the new field value to assign.
   

   :idx: the index to replace.
   

   :returns: false if the index was larger than any valid index, else true.

.. bro:id:: Broker::record_create

   :Type: :bro:type:`function` (sz: :bro:type:`count`) : :bro:type:`Broker::Data`

   Create communication data of type "record".
   

   :sz: the number of fields in the record.
   

   :returns: record data, with all fields uninitialized.

.. bro:id:: Broker::record_iterator

   :Type: :bro:type:`function` (r: :bro:type:`Broker::Data`) : :bro:type:`opaque` of Broker::RecordIterator

   Create an iterator for a record.  Note that this makes a copy of the record
   internally to ensure the iterator is always valid.
   

   :r: the record to iterate over.
   

   :returns: an iterator.

.. bro:id:: Broker::record_iterator_last

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::RecordIterator) : :bro:type:`bool`

   Check if there are no more elements to iterate over.
   

   :it: an iterator.
   

   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. bro:id:: Broker::record_iterator_next

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::RecordIterator) : :bro:type:`bool`

   Advance an iterator.
   

   :it: an iterator.
   

   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. bro:id:: Broker::record_iterator_value

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::RecordIterator) : :bro:type:`Broker::Data`

   Retrieve the data at an iterator's current position.
   

   :it: an iterator.
   

   :returns: element in the collection that the iterator currently references.

.. bro:id:: Broker::record_lookup

   :Type: :bro:type:`function` (r: :bro:type:`Broker::Data`, idx: :bro:type:`count`) : :bro:type:`Broker::Data`

   Lookup a field in a record at a particular position.
   

   :r: the record to query.
   

   :idx: the index to lookup.
   

   :returns: the value at the index.  The optional field of the returned record
            may not be set if the field of the record has no value or if the
            index was not valid.

.. bro:id:: Broker::record_size

   :Type: :bro:type:`function` (r: :bro:type:`Broker::Data`) : :bro:type:`count`

   Get the number of fields within a record.
   

   :r: the record to query.
   

   :returns: the number of fields in the record.

.. bro:id:: Broker::remove_from

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, i: :bro:type:`any`, e: :bro:type:`interval` :bro:attr:`&default` = ``0 secs`` :bro:attr:`&optional`) : :bro:type:`bool`

   Removes an element from an existing set or table.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :i: the index to remove from the set or table.
   

   :e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. bro:id:: Broker::set_clear

   :Type: :bro:type:`function` (s: :bro:type:`Broker::Data`) : :bro:type:`bool`

   Remove all elements within a set.
   

   :s: the set to clear.
   

   :returns: always true.

.. bro:id:: Broker::set_contains

   :Type: :bro:type:`function` (s: :bro:type:`Broker::Data`, key: :bro:type:`any`) : :bro:type:`bool`

   Check if a set contains a particular element.
   

   :s: the set to query.
   

   :key: the element to check for existence.
   

   :returns: true if the key exists in the set.

.. bro:id:: Broker::set_create

   :Type: :bro:type:`function` () : :bro:type:`Broker::Data`

   Create communication data of type "set".

.. bro:id:: Broker::set_insert

   :Type: :bro:type:`function` (s: :bro:type:`Broker::Data`, key: :bro:type:`any`) : :bro:type:`bool`

   Insert an element into a set.
   

   :s: the set to modify.
   

   :key: the element to insert.
   

   :returns: true if the key was inserted, or false if it already existed.

.. bro:id:: Broker::set_iterator

   :Type: :bro:type:`function` (s: :bro:type:`Broker::Data`) : :bro:type:`opaque` of Broker::SetIterator

   Create an iterator for a set.  Note that this makes a copy of the set
   internally to ensure the iterator is always valid.
   

   :s: the set to iterate over.
   

   :returns: an iterator.

.. bro:id:: Broker::set_iterator_last

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::SetIterator) : :bro:type:`bool`

   Check if there are no more elements to iterate over.
   

   :it: an iterator.
   

   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. bro:id:: Broker::set_iterator_next

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::SetIterator) : :bro:type:`bool`

   Advance an iterator.
   

   :it: an iterator.
   

   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. bro:id:: Broker::set_iterator_value

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::SetIterator) : :bro:type:`Broker::Data`

   Retrieve the data at an iterator's current position.
   

   :it: an iterator.
   

   :returns: element in the collection that the iterator currently references.

.. bro:id:: Broker::set_remove

   :Type: :bro:type:`function` (s: :bro:type:`Broker::Data`, key: :bro:type:`any`) : :bro:type:`bool`

   Remove an element from a set.
   

   :s: the set to modify.
   

   :key: the element to remove.
   

   :returns: true if the element existed in the set and is now removed.

.. bro:id:: Broker::set_size

   :Type: :bro:type:`function` (s: :bro:type:`Broker::Data`) : :bro:type:`count`

   Get the number of elements within a set.
   

   :s: the set to query.
   

   :returns: the number of elements in the set.

.. bro:id:: Broker::store_name

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store) : :bro:type:`string`

   Get the name of a store.
   

   :returns: the name of the store.

.. bro:id:: Broker::table_clear

   :Type: :bro:type:`function` (t: :bro:type:`Broker::Data`) : :bro:type:`bool`

   Remove all elements within a table.
   

   :t: the table to clear.
   

   :returns: always true.

.. bro:id:: Broker::table_contains

   :Type: :bro:type:`function` (t: :bro:type:`Broker::Data`, key: :bro:type:`any`) : :bro:type:`bool`

   Check if a table contains a particular key.
   

   :t: the table to query.
   

   :key: the key to check for existence.
   

   :returns: true if the key exists in the table.

.. bro:id:: Broker::table_create

   :Type: :bro:type:`function` () : :bro:type:`Broker::Data`

   Create communication data of type "table".

.. bro:id:: Broker::table_insert

   :Type: :bro:type:`function` (t: :bro:type:`Broker::Data`, key: :bro:type:`any`, val: :bro:type:`any`) : :bro:type:`Broker::Data`

   Insert a key-value pair into a table.
   

   :t: the table to modify.
   

   :key: the key at which to insert the value.
   

   :val: the value to insert.
   

   :returns: true if the key-value pair was inserted, or false if the key
            already existed in the table.

.. bro:id:: Broker::table_iterator

   :Type: :bro:type:`function` (t: :bro:type:`Broker::Data`) : :bro:type:`opaque` of Broker::TableIterator

   Create an iterator for a table.  Note that this makes a copy of the table
   internally to ensure the iterator is always valid.
   

   :t: the table to iterate over.
   

   :returns: an iterator.

.. bro:id:: Broker::table_iterator_last

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::TableIterator) : :bro:type:`bool`

   Check if there are no more elements to iterate over.
   

   :it: an iterator.
   

   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. bro:id:: Broker::table_iterator_next

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::TableIterator) : :bro:type:`bool`

   Advance an iterator.
   

   :it: an iterator.
   

   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. bro:id:: Broker::table_iterator_value

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::TableIterator) : :bro:type:`Broker::TableItem`

   Retrieve the data at an iterator's current position.
   

   :it: an iterator.
   

   :returns: element in the collection that the iterator currently references.

.. bro:id:: Broker::table_lookup

   :Type: :bro:type:`function` (t: :bro:type:`Broker::Data`, key: :bro:type:`any`) : :bro:type:`Broker::Data`

   Retrieve a value from a table.
   

   :t: the table to query.
   

   :key: the key to lookup.
   

   :returns: the value associated with the key.  If the key did not exist, then
            the optional field of the returned record is not set.

.. bro:id:: Broker::table_remove

   :Type: :bro:type:`function` (t: :bro:type:`Broker::Data`, key: :bro:type:`any`) : :bro:type:`Broker::Data`

   Remove a key-value pair from a table.
   

   :t: the table to modify.
   

   :key: the key to remove from the table.
   

   :returns: the value associated with the key.  If the key did not exist, then
            the optional field of the returned record is not set.

.. bro:id:: Broker::table_size

   :Type: :bro:type:`function` (t: :bro:type:`Broker::Data`) : :bro:type:`count`

   Get the number of elements within a table.
   

   :t: the table to query.
   

   :returns: the number of elements in the table.

.. bro:id:: Broker::vector_clear

   :Type: :bro:type:`function` (v: :bro:type:`Broker::Data`) : :bro:type:`bool`

   Remove all elements within a vector.
   

   :v: the vector to clear.
   

   :returns: always true.

.. bro:id:: Broker::vector_create

   :Type: :bro:type:`function` () : :bro:type:`Broker::Data`

   Create communication data of type "vector".

.. bro:id:: Broker::vector_insert

   :Type: :bro:type:`function` (v: :bro:type:`Broker::Data`, idx: :bro:type:`count`, d: :bro:type:`any`) : :bro:type:`bool`

   Insert an element into a vector at a particular position, possibly displacing
   existing elements (insertion always grows the size of the vector by one).
   

   :v: the vector to modify.
   

   :d: the element to insert.
   

   :idx: the index at which to insert the data.  If it is greater than the
        current size of the vector, the element is inserted at the end.
   

   :returns: always true.

.. bro:id:: Broker::vector_iterator

   :Type: :bro:type:`function` (v: :bro:type:`Broker::Data`) : :bro:type:`opaque` of Broker::VectorIterator

   Create an iterator for a vector.  Note that this makes a copy of the vector
   internally to ensure the iterator is always valid.
   

   :v: the vector to iterate over.
   

   :returns: an iterator.

.. bro:id:: Broker::vector_iterator_last

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::VectorIterator) : :bro:type:`bool`

   Check if there are no more elements to iterate over.
   

   :it: an iterator.
   

   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. bro:id:: Broker::vector_iterator_next

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::VectorIterator) : :bro:type:`bool`

   Advance an iterator.
   

   :it: an iterator.
   

   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. bro:id:: Broker::vector_iterator_value

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::VectorIterator) : :bro:type:`Broker::Data`

   Retrieve the data at an iterator's current position.
   

   :it: an iterator.
   

   :returns: element in the collection that the iterator currently references.

.. bro:id:: Broker::vector_lookup

   :Type: :bro:type:`function` (v: :bro:type:`Broker::Data`, idx: :bro:type:`count`) : :bro:type:`Broker::Data`

   Lookup an element in a vector at a particular position.
   

   :v: the vector to query.
   

   :idx: the index to lookup.
   

   :returns: the value at the index.  If the index was larger than any
            valid index, the optional field of the returned record is not set.

.. bro:id:: Broker::vector_remove

   :Type: :bro:type:`function` (v: :bro:type:`Broker::Data`, idx: :bro:type:`count`) : :bro:type:`Broker::Data`

   Remove an element from a vector at a particular position.
   

   :v: the vector to modify.
   

   :idx: the index to remove.
   

   :returns: the value that was just evicted.  If the index was larger than any
            valid index, the optional field of the returned record is not set.

.. bro:id:: Broker::vector_replace

   :Type: :bro:type:`function` (v: :bro:type:`Broker::Data`, idx: :bro:type:`count`, d: :bro:type:`any`) : :bro:type:`Broker::Data`

   Replace an element in a vector at a particular position.
   

   :v: the vector to modify.
   

   :d: the element to insert.
   

   :idx: the index to replace.
   

   :returns: the value that was just evicted.  If the index was larger than any
            valid index, the optional field of the returned record is not set.

.. bro:id:: Broker::vector_size

   :Type: :bro:type:`function` (v: :bro:type:`Broker::Data`) : :bro:type:`count`

   Get the number of elements within a vector.
   

   :v: the vector to query.
   

   :returns: the number of elements in the vector.


