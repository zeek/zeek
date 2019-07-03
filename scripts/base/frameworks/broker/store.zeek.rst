:tocdepth: 3

base/frameworks/broker/store.zeek
=================================
.. zeek:namespace:: Broker

The Broker-based data store API and its various options.

:Namespace: Broker
:Imports: :doc:`base/bif/data.bif.zeek </scripts/base/bif/data.bif.zeek>`, :doc:`base/bif/store.bif.zeek </scripts/base/bif/store.bif.zeek>`, :doc:`base/frameworks/broker/main.zeek </scripts/base/frameworks/broker/main.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
==================================================================================================== =======================================================================
:zeek:id:`Broker::default_clone_mutation_buffer_interval`: :zeek:type:`interval` :zeek:attr:`&redef` The maximum amount of time that a disconnected clone will
                                                                                                     buffer data store mutation commands.
:zeek:id:`Broker::default_clone_resync_interval`: :zeek:type:`interval` :zeek:attr:`&redef`          The default frequency at which clones will attempt to
                                                                                                     reconnect/resynchronize with their master in the event that they become
                                                                                                     disconnected.
:zeek:id:`Broker::default_clone_stale_interval`: :zeek:type:`interval` :zeek:attr:`&redef`           The duration after which a clone that is disconnected from its master
                                                                                                     will begin to treat its local cache as stale.
==================================================================================================== =======================================================================

Types
#####
======================================================== =====================================================
:zeek:type:`Broker::BackendOptions`: :zeek:type:`record` Options to tune the particular storage backends.
:zeek:type:`Broker::BackendType`: :zeek:type:`enum`      Enumerates the possible storage backends.
:zeek:type:`Broker::QueryResult`: :zeek:type:`record`    The result of a data store query.
:zeek:type:`Broker::QueryStatus`: :zeek:type:`enum`      Whether a data store query could be completed or not.
:zeek:type:`Broker::RocksDBOptions`: :zeek:type:`record` Options to tune the RocksDB storage backend.
:zeek:type:`Broker::SQLiteOptions`: :zeek:type:`record`  Options to tune the SQLite storage backend.
======================================================== =====================================================

Functions
#########
=============================================================== =============================================================================
:zeek:id:`Broker::append`: :zeek:type:`function`                Extends an existing string with another.
:zeek:id:`Broker::clear`: :zeek:type:`function`                 Deletes all of a store's content, it will be empty afterwards.
:zeek:id:`Broker::close`: :zeek:type:`function`                 Close a data store.
:zeek:id:`Broker::create_clone`: :zeek:type:`function`          Create a clone of a master data store which may live with a remote peer.
:zeek:id:`Broker::create_master`: :zeek:type:`function`         Create a master data store which contains key-value pairs.
:zeek:id:`Broker::data`: :zeek:type:`function`                  Convert any Zeek value to communication data.
:zeek:id:`Broker::data_type`: :zeek:type:`function`             Retrieve the type of data associated with communication data.
:zeek:id:`Broker::decrement`: :zeek:type:`function`             Decrements an existing value by a given amount.
:zeek:id:`Broker::erase`: :zeek:type:`function`                 Remove a key-value pair from the store.
:zeek:id:`Broker::exists`: :zeek:type:`function`                Check if a key exists in a data store.
:zeek:id:`Broker::get`: :zeek:type:`function`                   Lookup the value associated with a key in a data store.
:zeek:id:`Broker::get_index_from_value`: :zeek:type:`function`  Retrieve a specific index from an existing container value.
:zeek:id:`Broker::increment`: :zeek:type:`function`             Increments an existing value by a given amount.
:zeek:id:`Broker::insert_into_set`: :zeek:type:`function`       Inserts an element into an existing set.
:zeek:id:`Broker::insert_into_table`: :zeek:type:`function`     Inserts an element into an existing table.
:zeek:id:`Broker::is_closed`: :zeek:type:`function`             Check if a store is closed or not.
:zeek:id:`Broker::keys`: :zeek:type:`function`                  Returns a set with all of a store's keys.
:zeek:id:`Broker::pop`: :zeek:type:`function`                   Removes the last element of an existing vector.
:zeek:id:`Broker::push`: :zeek:type:`function`                  Appends an element to an existing vector.
:zeek:id:`Broker::put`: :zeek:type:`function`                   Insert a key-value pair in to the store.
:zeek:id:`Broker::put_unique`: :zeek:type:`function`            Insert a key-value pair in to the store, but only if the key does not
                                                                already exist.
:zeek:id:`Broker::record_assign`: :zeek:type:`function`         Replace a field in a record at a particular position.
:zeek:id:`Broker::record_create`: :zeek:type:`function`         Create communication data of type "record".
:zeek:id:`Broker::record_iterator`: :zeek:type:`function`       Create an iterator for a record.
:zeek:id:`Broker::record_iterator_last`: :zeek:type:`function`  Check if there are no more elements to iterate over.
:zeek:id:`Broker::record_iterator_next`: :zeek:type:`function`  Advance an iterator.
:zeek:id:`Broker::record_iterator_value`: :zeek:type:`function` Retrieve the data at an iterator's current position.
:zeek:id:`Broker::record_lookup`: :zeek:type:`function`         Lookup a field in a record at a particular position.
:zeek:id:`Broker::record_size`: :zeek:type:`function`           Get the number of fields within a record.
:zeek:id:`Broker::remove_from`: :zeek:type:`function`           Removes an element from an existing set or table.
:zeek:id:`Broker::set_clear`: :zeek:type:`function`             Remove all elements within a set.
:zeek:id:`Broker::set_contains`: :zeek:type:`function`          Check if a set contains a particular element.
:zeek:id:`Broker::set_create`: :zeek:type:`function`            Create communication data of type "set".
:zeek:id:`Broker::set_insert`: :zeek:type:`function`            Insert an element into a set.
:zeek:id:`Broker::set_iterator`: :zeek:type:`function`          Create an iterator for a set.
:zeek:id:`Broker::set_iterator_last`: :zeek:type:`function`     Check if there are no more elements to iterate over.
:zeek:id:`Broker::set_iterator_next`: :zeek:type:`function`     Advance an iterator.
:zeek:id:`Broker::set_iterator_value`: :zeek:type:`function`    Retrieve the data at an iterator's current position.
:zeek:id:`Broker::set_remove`: :zeek:type:`function`            Remove an element from a set.
:zeek:id:`Broker::set_size`: :zeek:type:`function`              Get the number of elements within a set.
:zeek:id:`Broker::store_name`: :zeek:type:`function`            Get the name of a store.
:zeek:id:`Broker::table_clear`: :zeek:type:`function`           Remove all elements within a table.
:zeek:id:`Broker::table_contains`: :zeek:type:`function`        Check if a table contains a particular key.
:zeek:id:`Broker::table_create`: :zeek:type:`function`          Create communication data of type "table".
:zeek:id:`Broker::table_insert`: :zeek:type:`function`          Insert a key-value pair into a table.
:zeek:id:`Broker::table_iterator`: :zeek:type:`function`        Create an iterator for a table.
:zeek:id:`Broker::table_iterator_last`: :zeek:type:`function`   Check if there are no more elements to iterate over.
:zeek:id:`Broker::table_iterator_next`: :zeek:type:`function`   Advance an iterator.
:zeek:id:`Broker::table_iterator_value`: :zeek:type:`function`  Retrieve the data at an iterator's current position.
:zeek:id:`Broker::table_lookup`: :zeek:type:`function`          Retrieve a value from a table.
:zeek:id:`Broker::table_remove`: :zeek:type:`function`          Remove a key-value pair from a table.
:zeek:id:`Broker::table_size`: :zeek:type:`function`            Get the number of elements within a table.
:zeek:id:`Broker::vector_clear`: :zeek:type:`function`          Remove all elements within a vector.
:zeek:id:`Broker::vector_create`: :zeek:type:`function`         Create communication data of type "vector".
:zeek:id:`Broker::vector_insert`: :zeek:type:`function`         Insert an element into a vector at a particular position, possibly displacing
                                                                existing elements (insertion always grows the size of the vector by one).
:zeek:id:`Broker::vector_iterator`: :zeek:type:`function`       Create an iterator for a vector.
:zeek:id:`Broker::vector_iterator_last`: :zeek:type:`function`  Check if there are no more elements to iterate over.
:zeek:id:`Broker::vector_iterator_next`: :zeek:type:`function`  Advance an iterator.
:zeek:id:`Broker::vector_iterator_value`: :zeek:type:`function` Retrieve the data at an iterator's current position.
:zeek:id:`Broker::vector_lookup`: :zeek:type:`function`         Lookup an element in a vector at a particular position.
:zeek:id:`Broker::vector_remove`: :zeek:type:`function`         Remove an element from a vector at a particular position.
:zeek:id:`Broker::vector_replace`: :zeek:type:`function`        Replace an element in a vector at a particular position.
:zeek:id:`Broker::vector_size`: :zeek:type:`function`           Get the number of elements within a vector.
=============================================================== =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Broker::default_clone_mutation_buffer_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2.0 mins``

   The maximum amount of time that a disconnected clone will
   buffer data store mutation commands.  If the clone reconnects before
   this time, it will replay all stored commands.  Note that this doesn't
   completely prevent the loss of store updates: all mutation messages
   are fire-and-forget and not explicitly acknowledged by the master.
   A negative/zero value indicates to never buffer commands.

.. zeek:id:: Broker::default_clone_resync_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 secs``

   The default frequency at which clones will attempt to
   reconnect/resynchronize with their master in the event that they become
   disconnected.

.. zeek:id:: Broker::default_clone_stale_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 mins``

   The duration after which a clone that is disconnected from its master
   will begin to treat its local cache as stale.  In the stale state,
   queries to the cache will timeout.  A negative value indicates that
   the local cache is never treated as stale.

Types
#####
.. zeek:type:: Broker::BackendOptions

   :Type: :zeek:type:`record`

      sqlite: :zeek:type:`Broker::SQLiteOptions` :zeek:attr:`&default` = ``[path=]`` :zeek:attr:`&optional`

      rocksdb: :zeek:type:`Broker::RocksDBOptions` :zeek:attr:`&default` = ``[path=]`` :zeek:attr:`&optional`

   Options to tune the particular storage backends.

.. zeek:type:: Broker::BackendType

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::MEMORY Broker::BackendType

      .. zeek:enum:: Broker::SQLITE Broker::BackendType

      .. zeek:enum:: Broker::ROCKSDB Broker::BackendType

   Enumerates the possible storage backends.

.. zeek:type:: Broker::QueryResult

   :Type: :zeek:type:`record`

      status: :zeek:type:`Broker::QueryStatus`
         Whether the query completed or not.

      result: :zeek:type:`Broker::Data`
         The result of the query.  Certain queries may use a particular
         data type (e.g. querying store size always returns a count, but
         a lookup may return various data types).

   The result of a data store query.

.. zeek:type:: Broker::QueryStatus

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::SUCCESS Broker::QueryStatus

      .. zeek:enum:: Broker::FAILURE Broker::QueryStatus

   Whether a data store query could be completed or not.

.. zeek:type:: Broker::RocksDBOptions

   :Type: :zeek:type:`record`

      path: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         File system path of the database.
         If left empty, will be derived from the name of the store,
         and use the '.rocksdb' file suffix.

   Options to tune the RocksDB storage backend.

.. zeek:type:: Broker::SQLiteOptions

   :Type: :zeek:type:`record`

      path: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         File system path of the database.
         If left empty, will be derived from the name of the store,
         and use the '.sqlite' file suffix.

   Options to tune the SQLite storage backend.

Functions
#########
.. zeek:id:: Broker::append

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, s: :zeek:type:`string`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Extends an existing string with another.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :s: the string to append.
   

   :e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::clear

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`bool`

   Deletes all of a store's content, it will be empty afterwards.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::close

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`bool`

   Close a data store.
   

   :h: a data store handle.
   

   :returns: true if store was valid and is now closed.  The handle can no
            longer be used for data store operations.

.. zeek:id:: Broker::create_clone

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, resync_interval: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_clone_resync_interval` :zeek:attr:`&optional`, stale_interval: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_clone_stale_interval` :zeek:attr:`&optional`, mutation_buffer_interval: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_clone_mutation_buffer_interval` :zeek:attr:`&optional`) : :zeek:type:`opaque` of Broker::Store

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

.. zeek:id:: Broker::create_master

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, b: :zeek:type:`Broker::BackendType` :zeek:attr:`&default` = ``Broker::MEMORY`` :zeek:attr:`&optional`, options: :zeek:type:`Broker::BackendOptions` :zeek:attr:`&default` = *[sqlite=[path=], rocksdb=[path=]]* :zeek:attr:`&optional`) : :zeek:type:`opaque` of Broker::Store

   Create a master data store which contains key-value pairs.
   

   :name: a unique name for the data store.
   

   :b: the storage backend to use.
   

   :options: tunes how some storage backends operate.
   

   :returns: a handle to the data store.

.. zeek:id:: Broker::data

   :Type: :zeek:type:`function` (d: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Convert any Zeek value to communication data.
   
   .. note:: Normally you won't need to use this function as data
      conversion happens implicitly when passing Zeek values into Broker
      functions.
   

   :d: any Zeek value to attempt to convert (not all types are supported).
   

   :returns: the converted communication data.  If the supplied Zeek data
            type does not support conversion to communication data, the
            returned record's optional field will not be set.

.. zeek:id:: Broker::data_type

   :Type: :zeek:type:`function` (d: :zeek:type:`Broker::Data`) : :zeek:type:`Broker::DataType`

   Retrieve the type of data associated with communication data.
   

   :d: the communication data.
   

   :returns: The data type associated with the communication data.
            Note that broker represents records in the same way as
            vectors, so there is no "record" type.

.. zeek:id:: Broker::decrement

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, a: :zeek:type:`any` :zeek:attr:`&default` = ``1`` :zeek:attr:`&optional`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Decrements an existing value by a given amount. This is supported for all
   numerical types, as well as for timestamps.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :amount: the amount to decrement the value by. 
   

   :e: the new expiration interval of the modified key. If null, the current
      expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::erase

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`) : :zeek:type:`bool`

   Remove a key-value pair from the store.
   

   :h: the handle of the store to modify.
   

   :k: the key to remove.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::exists

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`) : :zeek:type:`Broker::QueryResult`

   Check if a key exists in a data store.
   

   :h: the handle of the store to query.
   

   :k: the key to lookup.
   

   :returns: True if the key exists in the data store.

.. zeek:id:: Broker::get

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`) : :zeek:type:`Broker::QueryResult`

   Lookup the value associated with a key in a data store.
   

   :h: the handle of the store to query.
   

   :k: the key to lookup.
   

   :returns: the result of the query.

.. zeek:id:: Broker::get_index_from_value

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`) : :zeek:type:`Broker::QueryResult`

   Retrieve a specific index from an existing container value. This
   is supported for values of types set, table, and vector.
   

   :h: the handle of the store to query.
   

   :k: the key of the container value to lookup.
   

   :i: the index to retrieve from the container value.
   

   :returns: For tables and vectors, the value at the given index, or
            failure if the index doesn't exist. For sets, a boolean
            indicating whether the index exists. Returns failure if the key
            does not exist at all.

.. zeek:id:: Broker::increment

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, a: :zeek:type:`any` :zeek:attr:`&default` = ``1`` :zeek:attr:`&optional`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Increments an existing value by a given amount. This is supported for all
   numerical types, as well as for timestamps.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :a: the amount to increment the value by. 
   

   :e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::insert_into_set

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Inserts an element into an existing set.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :i: the index to insert into the set.
   

   :e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::insert_into_table

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Inserts an element into an existing table.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :i: the index to insert into the table
   

   :v: the value to associate with the index.
   

   :e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::is_closed

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`bool`

   Check if a store is closed or not.
   

   :returns: true if the store is closed.

.. zeek:id:: Broker::keys

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`Broker::QueryResult`

   Returns a set with all of a store's keys. The results reflect a snapshot
   in time that may diverge from reality soon afterwards.   When acessing
   any of the element, it may no longer actually be there. The function is
   also expensive for large stores, as it copies the complete set.
   

   :returns: a set with the keys.  If you expect the keys to be of
            non-uniform type, consider using
            :zeek:see:`Broker::set_iterator` to iterate over the result.

.. zeek:id:: Broker::pop

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Removes the last element of an existing vector.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::push

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Appends an element to an existing vector.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :b: the value to append to the vector.
   

   :e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::put

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Insert a key-value pair in to the store.
   

   :h: the handle of the store to modify.
   

   :k: the key to insert.
   

   :v: the value to insert.
   

   :e: the expiration interval of the key-value pair.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::put_unique

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`Broker::QueryResult`

   Insert a key-value pair in to the store, but only if the key does not
   already exist.
   

   :h: the handle of the store to modify.
   

   :k: the key to insert.
   

   :v: the value to insert.
   

   :e: the expiration interval of the key-value pair.
   

   :returns: the result of the query which is a boolean data value that is
            true if the insertion happened, or false if it was rejected
            due to the key already existing.

.. zeek:id:: Broker::record_assign

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`bool`

   Replace a field in a record at a particular position.
   

   :r: the record to modify.
   

   :d: the new field value to assign.
   

   :idx: the index to replace.
   

   :returns: false if the index was larger than any valid index, else true.

.. zeek:id:: Broker::record_create

   :Type: :zeek:type:`function` (sz: :zeek:type:`count`) : :zeek:type:`Broker::Data`

   Create communication data of type "record".
   

   :sz: the number of fields in the record.
   

   :returns: record data, with all fields uninitialized.

.. zeek:id:: Broker::record_iterator

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::RecordIterator

   Create an iterator for a record.  Note that this makes a copy of the record
   internally to ensure the iterator is always valid.
   

   :r: the record to iterate over.
   

   :returns: an iterator.

.. zeek:id:: Broker::record_iterator_last

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`bool`

   Check if there are no more elements to iterate over.
   

   :it: an iterator.
   

   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. zeek:id:: Broker::record_iterator_next

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`bool`

   Advance an iterator.
   

   :it: an iterator.
   

   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. zeek:id:: Broker::record_iterator_value

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`Broker::Data`

   Retrieve the data at an iterator's current position.
   

   :it: an iterator.
   

   :returns: element in the collection that the iterator currently references.

.. zeek:id:: Broker::record_lookup

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`

   Lookup a field in a record at a particular position.
   

   :r: the record to query.
   

   :idx: the index to lookup.
   

   :returns: the value at the index.  The optional field of the returned record
            may not be set if the field of the record has no value or if the
            index was not valid.

.. zeek:id:: Broker::record_size

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`) : :zeek:type:`count`

   Get the number of fields within a record.
   

   :r: the record to query.
   

   :returns: the number of fields in the record.

.. zeek:id:: Broker::remove_from

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Removes an element from an existing set or table.
   

   :h: the handle of the store to modify.
   

   :k: the key whose associated value is to be modified. The key must
      already exist.
   

   :i: the index to remove from the set or table.
   

   :e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::set_clear

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`bool`

   Remove all elements within a set.
   

   :s: the set to clear.
   

   :returns: always true.

.. zeek:id:: Broker::set_contains

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`

   Check if a set contains a particular element.
   

   :s: the set to query.
   

   :key: the element to check for existence.
   

   :returns: true if the key exists in the set.

.. zeek:id:: Broker::set_create

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`

   Create communication data of type "set".

.. zeek:id:: Broker::set_insert

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`

   Insert an element into a set.
   

   :s: the set to modify.
   

   :key: the element to insert.
   

   :returns: true if the key was inserted, or false if it already existed.

.. zeek:id:: Broker::set_iterator

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::SetIterator

   Create an iterator for a set.  Note that this makes a copy of the set
   internally to ensure the iterator is always valid.
   

   :s: the set to iterate over.
   

   :returns: an iterator.

.. zeek:id:: Broker::set_iterator_last

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`bool`

   Check if there are no more elements to iterate over.
   

   :it: an iterator.
   

   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. zeek:id:: Broker::set_iterator_next

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`bool`

   Advance an iterator.
   

   :it: an iterator.
   

   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. zeek:id:: Broker::set_iterator_value

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`Broker::Data`

   Retrieve the data at an iterator's current position.
   

   :it: an iterator.
   

   :returns: element in the collection that the iterator currently references.

.. zeek:id:: Broker::set_remove

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`

   Remove an element from a set.
   

   :s: the set to modify.
   

   :key: the element to remove.
   

   :returns: true if the element existed in the set and is now removed.

.. zeek:id:: Broker::set_size

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`count`

   Get the number of elements within a set.
   

   :s: the set to query.
   

   :returns: the number of elements in the set.

.. zeek:id:: Broker::store_name

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`string`

   Get the name of a store.
   

   :returns: the name of the store.

.. zeek:id:: Broker::table_clear

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`bool`

   Remove all elements within a table.
   

   :t: the table to clear.
   

   :returns: always true.

.. zeek:id:: Broker::table_contains

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`

   Check if a table contains a particular key.
   

   :t: the table to query.
   

   :key: the key to check for existence.
   

   :returns: true if the key exists in the table.

.. zeek:id:: Broker::table_create

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`

   Create communication data of type "table".

.. zeek:id:: Broker::table_insert

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`, val: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Insert a key-value pair into a table.
   

   :t: the table to modify.
   

   :key: the key at which to insert the value.
   

   :val: the value to insert.
   

   :returns: true if the key-value pair was inserted, or false if the key
            already existed in the table.

.. zeek:id:: Broker::table_iterator

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::TableIterator

   Create an iterator for a table.  Note that this makes a copy of the table
   internally to ensure the iterator is always valid.
   

   :t: the table to iterate over.
   

   :returns: an iterator.

.. zeek:id:: Broker::table_iterator_last

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`bool`

   Check if there are no more elements to iterate over.
   

   :it: an iterator.
   

   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. zeek:id:: Broker::table_iterator_next

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`bool`

   Advance an iterator.
   

   :it: an iterator.
   

   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. zeek:id:: Broker::table_iterator_value

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`Broker::TableItem`

   Retrieve the data at an iterator's current position.
   

   :it: an iterator.
   

   :returns: element in the collection that the iterator currently references.

.. zeek:id:: Broker::table_lookup

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Retrieve a value from a table.
   

   :t: the table to query.
   

   :key: the key to lookup.
   

   :returns: the value associated with the key.  If the key did not exist, then
            the optional field of the returned record is not set.

.. zeek:id:: Broker::table_remove

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Remove a key-value pair from a table.
   

   :t: the table to modify.
   

   :key: the key to remove from the table.
   

   :returns: the value associated with the key.  If the key did not exist, then
            the optional field of the returned record is not set.

.. zeek:id:: Broker::table_size

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`count`

   Get the number of elements within a table.
   

   :t: the table to query.
   

   :returns: the number of elements in the table.

.. zeek:id:: Broker::vector_clear

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`bool`

   Remove all elements within a vector.
   

   :v: the vector to clear.
   

   :returns: always true.

.. zeek:id:: Broker::vector_create

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`

   Create communication data of type "vector".

.. zeek:id:: Broker::vector_insert

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`bool`

   Insert an element into a vector at a particular position, possibly displacing
   existing elements (insertion always grows the size of the vector by one).
   

   :v: the vector to modify.
   

   :d: the element to insert.
   

   :idx: the index at which to insert the data.  If it is greater than the
        current size of the vector, the element is inserted at the end.
   

   :returns: always true.

.. zeek:id:: Broker::vector_iterator

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::VectorIterator

   Create an iterator for a vector.  Note that this makes a copy of the vector
   internally to ensure the iterator is always valid.
   

   :v: the vector to iterate over.
   

   :returns: an iterator.

.. zeek:id:: Broker::vector_iterator_last

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`bool`

   Check if there are no more elements to iterate over.
   

   :it: an iterator.
   

   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. zeek:id:: Broker::vector_iterator_next

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`bool`

   Advance an iterator.
   

   :it: an iterator.
   

   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. zeek:id:: Broker::vector_iterator_value

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`Broker::Data`

   Retrieve the data at an iterator's current position.
   

   :it: an iterator.
   

   :returns: element in the collection that the iterator currently references.

.. zeek:id:: Broker::vector_lookup

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`

   Lookup an element in a vector at a particular position.
   

   :v: the vector to query.
   

   :idx: the index to lookup.
   

   :returns: the value at the index.  If the index was larger than any
            valid index, the optional field of the returned record is not set.

.. zeek:id:: Broker::vector_remove

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`

   Remove an element from a vector at a particular position.
   

   :v: the vector to modify.
   

   :idx: the index to remove.
   

   :returns: the value that was just evicted.  If the index was larger than any
            valid index, the optional field of the returned record is not set.

.. zeek:id:: Broker::vector_replace

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Replace an element in a vector at a particular position.
   

   :v: the vector to modify.
   

   :d: the element to insert.
   

   :idx: the index to replace.
   

   :returns: the value that was just evicted.  If the index was larger than any
            valid index, the optional field of the returned record is not set.

.. zeek:id:: Broker::vector_size

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`count`

   Get the number of elements within a vector.
   

   :v: the vector to query.
   

   :returns: the number of elements in the vector.


