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
==================================================================================================== ==========================================================================
:zeek:id:`Broker::default_clone_mutation_buffer_interval`: :zeek:type:`interval` :zeek:attr:`&redef` The maximum amount of time that a disconnected clone will
                                                                                                     buffer data store mutation commands.
:zeek:id:`Broker::default_clone_resync_interval`: :zeek:type:`interval` :zeek:attr:`&redef`          The default frequency at which clones will attempt to
                                                                                                     reconnect/resynchronize with their master in the event that they become
                                                                                                     disconnected.
:zeek:id:`Broker::default_clone_stale_interval`: :zeek:type:`interval` :zeek:attr:`&redef`           The duration after which a clone that is disconnected from its master
                                                                                                     will begin to treat its local cache as stale.
:zeek:id:`Broker::table_store_db_directory`: :zeek:type:`string` :zeek:attr:`&redef`                 The directory used for storing persistent database files when using Broker
                                                                                                     store backed Zeek tables.
:zeek:id:`Broker::table_store_master`: :zeek:type:`bool` :zeek:attr:`&redef`                         If set to true, the current node is the master node for Broker stores
                                                                                                     backing Zeek tables.
==================================================================================================== ==========================================================================

Types
#####
========================================================= =============================================================
:zeek:type:`Broker::BackendOptions`: :zeek:type:`record`  Options to tune the particular storage backends.
:zeek:type:`Broker::BackendType`: :zeek:type:`enum`       Enumerates the possible storage backends.
:zeek:type:`Broker::QueryResult`: :zeek:type:`record`     The result of a data store query.
:zeek:type:`Broker::QueryStatus`: :zeek:type:`enum`       Whether a data store query could be completed or not.
:zeek:type:`Broker::SQLiteFailureMode`: :zeek:type:`enum` Behavior when the SQLite database file is found to be corrupt
                                                          or otherwise fails to open or initialize.
:zeek:type:`Broker::SQLiteJournalMode`: :zeek:type:`enum` Values supported for SQLite's PRAGMA journal_mode statement.
:zeek:type:`Broker::SQLiteOptions`: :zeek:type:`record`   Options to tune the SQLite storage backend.
:zeek:type:`Broker::SQLiteSynchronous`: :zeek:type:`enum` Values supported for SQLite's PRAGMA synchronous statement.
========================================================= =============================================================

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
:zeek:id:`Broker::put`: :zeek:type:`function`                   Insert a key-value pair into the store.
:zeek:id:`Broker::put_unique`: :zeek:type:`function`            Insert a key-value pair into the store, but only if the key does not
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
   :source-code: base/frameworks/broker/store.zeek 26 26

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
   :source-code: base/frameworks/broker/store.zeek 12 12

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 secs``

   The default frequency at which clones will attempt to
   reconnect/resynchronize with their master in the event that they become
   disconnected.

.. zeek:id:: Broker::default_clone_stale_interval
   :source-code: base/frameworks/broker/store.zeek 18 18

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 mins``

   The duration after which a clone that is disconnected from its master
   will begin to treat its local cache as stale.  In the stale state,
   queries to the cache will timeout.  A negative value indicates that
   the local cache is never treated as stale.

.. zeek:id:: Broker::table_store_db_directory
   :source-code: base/frameworks/broker/store.zeek 36 36

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"."``

   The directory used for storing persistent database files when using Broker
   store backed Zeek tables.

.. zeek:id:: Broker::table_store_master
   :source-code: base/frameworks/broker/store.zeek 32 32

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If set to true, the current node is the master node for Broker stores
   backing Zeek tables. By default this value will be automatically set to
   true in standalone mode, and on the manager node of a cluster. This value
   should not typically be changed manually.

Types
#####
.. zeek:type:: Broker::BackendOptions
   :source-code: base/frameworks/broker/store.zeek 119 121

   :Type: :zeek:type:`record`

      sqlite: :zeek:type:`Broker::SQLiteOptions` :zeek:attr:`&default` = *[path=, synchronous=<uninitialized>, journal_mode=<uninitialized>, failure_mode=Broker::SQLITE_FAILURE_MODE_FAIL, integrity_check=F]* :zeek:attr:`&optional`

   Options to tune the particular storage backends.

.. zeek:type:: Broker::BackendType
   :source-code: base/frameworks/broker/store.zeek 55 55

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::MEMORY Broker::BackendType

      .. zeek:enum:: Broker::SQLITE Broker::BackendType

   Enumerates the possible storage backends.

.. zeek:type:: Broker::QueryResult
   :source-code: base/frameworks/broker/store.zeek 45 52

   :Type: :zeek:type:`record`

      status: :zeek:type:`Broker::QueryStatus`
         Whether the query completed or not.

      result: :zeek:type:`Broker::Data`
         The result of the query.  Certain queries may use a particular
         data type (e.g. querying store size always returns a count, but
         a lookup may return various data types).

   The result of a data store query.

.. zeek:type:: Broker::QueryStatus
   :source-code: base/frameworks/broker/store.zeek 39 43

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::SUCCESS Broker::QueryStatus

      .. zeek:enum:: Broker::FAILURE Broker::QueryStatus

   Whether a data store query could be completed or not.

.. zeek:type:: Broker::SQLiteFailureMode
   :source-code: base/frameworks/broker/store.zeek 62 66

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::SQLITE_FAILURE_MODE_FAIL Broker::SQLiteFailureMode

         Fail during initialization.

      .. zeek:enum:: Broker::SQLITE_FAILURE_MODE_DELETE Broker::SQLiteFailureMode

         Attempt to delete the database file and retry.

   Behavior when the SQLite database file is found to be corrupt
   or otherwise fails to open or initialize.

.. zeek:type:: Broker::SQLiteJournalMode
   :source-code: base/frameworks/broker/store.zeek 76 80

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::SQLITE_JOURNAL_MODE_DELETE Broker::SQLiteJournalMode

      .. zeek:enum:: Broker::SQLITE_JOURNAL_MODE_WAL Broker::SQLiteJournalMode

   Values supported for SQLite's PRAGMA journal_mode statement.

.. zeek:type:: Broker::SQLiteOptions
   :source-code: base/frameworks/broker/store.zeek 82 116

   :Type: :zeek:type:`record`

      path: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         File system path of the database.
         If left empty, will be derived from the name of the store,
         and use the '.sqlite' file suffix.

      synchronous: :zeek:type:`Broker::SQLiteSynchronous` :zeek:attr:`&optional`
         If set, runs the PRAGMA synchronous statement with the
         provided value after connecting to the SQLite database. See
         `SQLite's synchronous documentation <https://www.sqlite.org/pragma.html#pragma_synchronous>`_
         for more details around performance and data safety trade offs.

      journal_mode: :zeek:type:`Broker::SQLiteJournalMode` :zeek:attr:`&optional`
         If set, runs the PRAGMA journal_mode statement with the
         provided value after connecting to the SQLite database. See
         `SQLite's journal_mode documentation <https://www.sqlite.org/pragma.html#pragma_journal_mode>`_
         for more details around performance, data safety trade offs
         and interaction with the PRAGMA synchronous statement.

      failure_mode: :zeek:type:`Broker::SQLiteFailureMode` :zeek:attr:`&default` = ``Broker::SQLITE_FAILURE_MODE_FAIL`` :zeek:attr:`&optional`
         What to do when the database is found corrupt during
         initialization. When set to SQLITE_FAILURE_MODE_DELETE,
         the old file is deleted to allow creation of a new and empty
         database. By default, an error is reported, the corrupt
         database file left in place and the data store is in a
         non-functional state.

      integrity_check: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         When true, run the PRAGMA integrity_check statement after
         opening the database and fail according to ``failure_mode``.
         PRAGMA integrity_check may take a non-negligible amount of time,
         so you are advised to experiment with the expected sizes
         of your databases if that is acceptable. Corrupted databases
         should be reliably detected when this setting is ``T``.

   Options to tune the SQLite storage backend.

.. zeek:type:: Broker::SQLiteSynchronous
   :source-code: base/frameworks/broker/store.zeek 68 74

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::SQLITE_SYNCHRONOUS_OFF Broker::SQLiteSynchronous

      .. zeek:enum:: Broker::SQLITE_SYNCHRONOUS_NORMAL Broker::SQLiteSynchronous

      .. zeek:enum:: Broker::SQLITE_SYNCHRONOUS_FULL Broker::SQLiteSynchronous

      .. zeek:enum:: Broker::SQLITE_SYNCHRONOUS_EXTRA Broker::SQLiteSynchronous

   Values supported for SQLite's PRAGMA synchronous statement.

Functions
#########
.. zeek:id:: Broker::append
   :source-code: base/frameworks/broker/store.zeek 853 856

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, s: :zeek:type:`string`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Extends an existing string with another.
   

   :param h: the handle of the store to modify.
   

   :param k: the key whose associated value is to be modified. The key must
      already exist.
   

   :param s: the string to append.
   

   :param e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::clear
   :source-code: base/frameworks/broker/store.zeek 883 886

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`bool`

   Deletes all of a store's content, it will be empty afterwards.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::close
   :source-code: base/frameworks/broker/store.zeek 792 795

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`bool`

   Close a data store.
   

   :param h: a data store handle.
   

   :returns: true if store was valid and is now closed.  The handle can no
            longer be used for data store operations.

.. zeek:id:: Broker::create_clone
   :source-code: base/frameworks/broker/store.zeek 786 790

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, resync_interval: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_clone_resync_interval` :zeek:attr:`&optional`, stale_interval: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_clone_stale_interval` :zeek:attr:`&optional`, mutation_buffer_interval: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_clone_mutation_buffer_interval` :zeek:attr:`&optional`) : :zeek:type:`opaque` of Broker::Store

   Create a clone of a master data store which may live with a remote peer.
   A clone automatically synchronizes to the master by
   receiving modifications and applying them locally.  Direct modifications
   are not possible, they must be sent through the master store, which then
   automatically broadcasts the changes out to clones.  But queries may be
   made directly against the local cloned copy, which may be resolved
   quicker than reaching out to a remote master store.
   

   :param name: the unique name which identifies the master data store.
   

   :param resync_interval: the frequency at which a clone that is disconnected from
                    its master attempts to reconnect with it.
   

   :param stale_interval: the duration after which a clone that is disconnected
                   from its master will begin to treat its local cache as
                   stale.  In this state, queries to the clone will timeout.
                   A negative value indicates that the local cache is never
                   treated as stale.
   

   :param mutation_buffer_interval: the amount of time to buffer data store update
                             messages once a clone detects its master is
                             unavailable.  If the clone reconnects before
                             this time, it will replay all buffered
                             commands.  Note that this doesn't completely
                             prevent the loss of store updates: all mutation
                             messages are fire-and-forget and not explicitly
                             acknowledged by the master.  A negative/zero
                             value indicates that commands never buffer.
   

   :returns: a handle to the data store for which a subsequent call to
            :zeek:see:`Broker::is_closed` will return true if the store
            could not be created/opened.

.. zeek:id:: Broker::create_master
   :source-code: base/frameworks/broker/store.zeek 778 781

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, b: :zeek:type:`Broker::BackendType` :zeek:attr:`&default` = ``Broker::MEMORY`` :zeek:attr:`&optional`, options: :zeek:type:`Broker::BackendOptions` :zeek:attr:`&default` = *[sqlite=[path=, synchronous=<uninitialized>, journal_mode=<uninitialized>, failure_mode=Broker::SQLITE_FAILURE_MODE_FAIL, integrity_check=F]]* :zeek:attr:`&optional`) : :zeek:type:`opaque` of Broker::Store

   Create a master data store which contains key-value pairs.
   

   :param name: a unique name for the data store.
   

   :param b: the storage backend to use.
   

   :param options: tunes how some storage backends operate.
   

   :returns: a handle to the data store for which a subsequent call to
            :zeek:see:`Broker::is_closed` will return true if the store
            could not be created/opened.

.. zeek:id:: Broker::data
   :source-code: base/frameworks/broker/store.zeek 893 896

   :Type: :zeek:type:`function` (d: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Convert any Zeek value to communication data.
   
   .. note:: Normally you won't need to use this function as data
      conversion happens implicitly when passing Zeek values into Broker
      functions.
   

   :param d: any Zeek value to attempt to convert (not all types are supported).
   

   :returns: the converted communication data.  If the supplied Zeek data
            type does not support conversion to communication data, the
            returned record's optional field will not be set.

.. zeek:id:: Broker::data_type
   :source-code: base/frameworks/broker/store.zeek 888 891

   :Type: :zeek:type:`function` (d: :zeek:type:`Broker::Data`) : :zeek:type:`Broker::DataType`

   Retrieve the type of data associated with communication data.
   

   :param d: the communication data.
   

   :returns: The data type associated with the communication data.
            Note that Broker represents records in the same way as
            vectors, so there is no "record" type.

.. zeek:id:: Broker::decrement
   :source-code: base/frameworks/broker/store.zeek 848 851

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, a: :zeek:type:`any` :zeek:attr:`&default` = ``1`` :zeek:attr:`&optional`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Decrements an existing value by a given amount. This is supported for all
   numerical types, as well as for timestamps.
   

   :param h: the handle of the store to modify.
   

   :param k: the key whose associated value is to be modified. The key must
      already exist.
   

   :param amount: the amount to decrement the value by.
   

   :param e: the new expiration interval of the modified key. If null, the current
      expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::erase
   :source-code: base/frameworks/broker/store.zeek 838 841

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`) : :zeek:type:`bool`

   Remove a key-value pair from the store.
   

   :param h: the handle of the store to modify.
   

   :param k: the key to remove.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::exists
   :source-code: base/frameworks/broker/store.zeek 807 810

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`) : :zeek:type:`Broker::QueryResult`

   Check if a key exists in a data store.
   

   :param h: the handle of the store to query.
   

   :param k: the key to lookup.
   

   :returns: True if the key exists in the data store.

.. zeek:id:: Broker::get
   :source-code: base/frameworks/broker/store.zeek 812 815

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`) : :zeek:type:`Broker::QueryResult`

   Lookup the value associated with a key in a data store.
   

   :param h: the handle of the store to query.
   

   :param k: the key to lookup.
   

   :returns: the result of the query.

.. zeek:id:: Broker::get_index_from_value
   :source-code: base/frameworks/broker/store.zeek 823 826

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`) : :zeek:type:`Broker::QueryResult`

   Retrieve a specific index from an existing container value. This
   is supported for values of types set, table, and vector.
   

   :param h: the handle of the store to query.
   

   :param k: the key of the container value to lookup.
   

   :param i: the index to retrieve from the container value.
   

   :returns: For tables and vectors, the value at the given index, or
            failure if the index doesn't exist. For sets, a boolean
            indicating whether the index exists. Returns failure if the key
            does not exist at all.

.. zeek:id:: Broker::increment
   :source-code: base/frameworks/broker/store.zeek 843 846

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, a: :zeek:type:`any` :zeek:attr:`&default` = ``1`` :zeek:attr:`&optional`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Increments an existing value by a given amount. This is supported for all
   numerical types, as well as for timestamps.
   

   :param h: the handle of the store to modify.
   

   :param k: the key whose associated value is to be modified. The key must
      already exist.
   

   :param a: the amount to increment the value by.
   

   :param e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::insert_into_set
   :source-code: base/frameworks/broker/store.zeek 858 861

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Inserts an element into an existing set.
   

   :param h: the handle of the store to modify.
   

   :param k: the key whose associated value is to be modified. The key must
      already exist.
   

   :param i: the index to insert into the set.
   

   :param e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::insert_into_table
   :source-code: base/frameworks/broker/store.zeek 863 866

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Inserts an element into an existing table.
   

   :param h: the handle of the store to modify.
   

   :param k: the key whose associated value is to be modified. The key must
      already exist.
   

   :param i: the index to insert into the table
   

   :param v: the value to associate with the index.
   

   :param e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::is_closed
   :source-code: base/frameworks/broker/store.zeek 797 800

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`bool`

   Check if a store is closed or not.
   

   :returns: true if the store is closed.

.. zeek:id:: Broker::keys
   :source-code: base/frameworks/broker/store.zeek 828 831

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`Broker::QueryResult`

   Returns a set with all of a store's keys. The results reflect a snapshot
   in time that may diverge from reality soon afterwards.   When accessing
   any of the element, it may no longer actually be there. The function is
   also expensive for large stores, as it copies the complete set.
   

   :returns: a set with the keys.  If you expect the keys to be of
            non-uniform type, consider using
            :zeek:see:`Broker::set_iterator` to iterate over the result.

.. zeek:id:: Broker::pop
   :source-code: base/frameworks/broker/store.zeek 878 881

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Removes the last element of an existing vector.
   

   :param h: the handle of the store to modify.
   

   :param k: the key whose associated value is to be modified. The key must
      already exist.
   

   :param e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::push
   :source-code: base/frameworks/broker/store.zeek 873 876

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Appends an element to an existing vector.
   

   :param h: the handle of the store to modify.
   

   :param k: the key whose associated value is to be modified. The key must
      already exist.
   

   :param b: the value to append to the vector.
   

   :param e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::put
   :source-code: base/frameworks/broker/store.zeek 833 836

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Insert a key-value pair into the store.
   

   :param h: the handle of the store to modify.
   

   :param k: the key to insert.
   

   :param v: the value to insert.
   

   :param e: the expiration interval of the key-value pair.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::put_unique
   :source-code: base/frameworks/broker/store.zeek 818 821

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`Broker::QueryResult`

   Insert a key-value pair into the store, but only if the key does not
   already exist.
   

   :param h: the handle of the store to modify.
   

   :param k: the key to insert.
   

   :param v: the value to insert.
   

   :param e: the expiration interval of the key-value pair.
   

   :returns: the result of the query which is a boolean data value that is
            true if the insertion happened, or false if it was rejected
            due to the key already existing.

.. zeek:id:: Broker::record_assign
   :source-code: base/frameworks/broker/store.zeek 1068 1071

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`bool`

   Replace a field in a record at a particular position.
   

   :param r: the record to modify.
   

   :param d: the new field value to assign.
   

   :param idx: the index to replace.
   

   :returns: false if the index was larger than any valid index, else true.

.. zeek:id:: Broker::record_create
   :source-code: base/frameworks/broker/store.zeek 1058 1061

   :Type: :zeek:type:`function` (sz: :zeek:type:`count`) : :zeek:type:`Broker::Data`

   Create communication data of type "record".
   

   :param sz: the number of fields in the record.
   

   :returns: record data, with all fields uninitialized.

.. zeek:id:: Broker::record_iterator
   :source-code: base/frameworks/broker/store.zeek 1078 1081

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::RecordIterator

   Create an iterator for a record.  Note that this makes a copy of the record
   internally to ensure the iterator is always valid.
   

   :param r: the record to iterate over.
   

   :returns: an iterator.

.. zeek:id:: Broker::record_iterator_last
   :source-code: base/frameworks/broker/store.zeek 1083 1086

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`bool`

   Check if there are no more elements to iterate over.
   

   :param it: an iterator.
   

   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. zeek:id:: Broker::record_iterator_next
   :source-code: base/frameworks/broker/store.zeek 1088 1091

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`bool`

   Advance an iterator.
   

   :param it: an iterator.
   

   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. zeek:id:: Broker::record_iterator_value
   :source-code: base/frameworks/broker/store.zeek 1093 1096

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`Broker::Data`

   Retrieve the data at an iterator's current position.
   

   :param it: an iterator.
   

   :returns: element in the collection that the iterator currently references.

.. zeek:id:: Broker::record_lookup
   :source-code: base/frameworks/broker/store.zeek 1073 1076

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`

   Lookup a field in a record at a particular position.
   

   :param r: the record to query.
   

   :param idx: the index to lookup.
   

   :returns: the value at the index.  The optional field of the returned record
            may not be set if the field of the record has no value or if the
            index was not valid.

.. zeek:id:: Broker::record_size
   :source-code: base/frameworks/broker/store.zeek 1063 1066

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`) : :zeek:type:`count`

   Get the number of fields within a record.
   

   :param r: the record to query.
   

   :returns: the number of fields in the record.

.. zeek:id:: Broker::remove_from
   :source-code: base/frameworks/broker/store.zeek 868 871

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`, e: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Removes an element from an existing set or table.
   

   :param h: the handle of the store to modify.
   

   :param k: the key whose associated value is to be modified. The key must
      already exist.
   

   :param i: the index to remove from the set or table.
   

   :param e: the new expiration interval of the modified key. If null, the
      current expiration time isn't changed.
   

   :returns: false if the store handle was not valid.

.. zeek:id:: Broker::set_clear
   :source-code: base/frameworks/broker/store.zeek 903 906

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`bool`

   Remove all elements within a set.
   

   :param s: the set to clear.
   

   :returns: always true.

.. zeek:id:: Broker::set_contains
   :source-code: base/frameworks/broker/store.zeek 913 916

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`

   Check if a set contains a particular element.
   

   :param s: the set to query.
   

   :param key: the element to check for existence.
   

   :returns: true if the key exists in the set.

.. zeek:id:: Broker::set_create
   :source-code: base/frameworks/broker/store.zeek 898 901

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`

   Create communication data of type "set".

.. zeek:id:: Broker::set_insert
   :source-code: base/frameworks/broker/store.zeek 918 921

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`

   Insert an element into a set.
   

   :param s: the set to modify.
   

   :param key: the element to insert.
   

   :returns: true if the key was inserted, or false if it already existed.

.. zeek:id:: Broker::set_iterator
   :source-code: base/frameworks/broker/store.zeek 928 931

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::SetIterator

   Create an iterator for a set.  Note that this makes a copy of the set
   internally to ensure the iterator is always valid.
   

   :param s: the set to iterate over.
   

   :returns: an iterator.

.. zeek:id:: Broker::set_iterator_last
   :source-code: base/frameworks/broker/store.zeek 933 936

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`bool`

   Check if there are no more elements to iterate over.
   

   :param it: an iterator.
   

   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. zeek:id:: Broker::set_iterator_next
   :source-code: base/frameworks/broker/store.zeek 938 941

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`bool`

   Advance an iterator.
   

   :param it: an iterator.
   

   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. zeek:id:: Broker::set_iterator_value
   :source-code: base/frameworks/broker/store.zeek 943 946

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`Broker::Data`

   Retrieve the data at an iterator's current position.
   

   :param it: an iterator.
   

   :returns: element in the collection that the iterator currently references.

.. zeek:id:: Broker::set_remove
   :source-code: base/frameworks/broker/store.zeek 923 926

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`

   Remove an element from a set.
   

   :param s: the set to modify.
   

   :param key: the element to remove.
   

   :returns: true if the element existed in the set and is now removed.

.. zeek:id:: Broker::set_size
   :source-code: base/frameworks/broker/store.zeek 908 911

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`count`

   Get the number of elements within a set.
   

   :param s: the set to query.
   

   :returns: the number of elements in the set.

.. zeek:id:: Broker::store_name
   :source-code: base/frameworks/broker/store.zeek 802 805

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`string`

   Get the name of a store.
   

   :returns: the name of the store.

.. zeek:id:: Broker::table_clear
   :source-code: base/frameworks/broker/store.zeek 953 956

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`bool`

   Remove all elements within a table.
   

   :param t: the table to clear.
   

   :returns: always true.

.. zeek:id:: Broker::table_contains
   :source-code: base/frameworks/broker/store.zeek 963 966

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`

   Check if a table contains a particular key.
   

   :param t: the table to query.
   

   :param key: the key to check for existence.
   

   :returns: true if the key exists in the table.

.. zeek:id:: Broker::table_create
   :source-code: base/frameworks/broker/store.zeek 948 951

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`

   Create communication data of type "table".

.. zeek:id:: Broker::table_insert
   :source-code: base/frameworks/broker/store.zeek 968 971

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`, val: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Insert a key-value pair into a table.
   

   :param t: the table to modify.
   

   :param key: the key at which to insert the value.
   

   :param val: the value to insert.
   

   :returns: true if the key-value pair was inserted, or false if the key
            already existed in the table.

.. zeek:id:: Broker::table_iterator
   :source-code: base/frameworks/broker/store.zeek 983 986

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::TableIterator

   Create an iterator for a table.  Note that this makes a copy of the table
   internally to ensure the iterator is always valid.
   

   :param t: the table to iterate over.
   

   :returns: an iterator.

.. zeek:id:: Broker::table_iterator_last
   :source-code: base/frameworks/broker/store.zeek 988 991

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`bool`

   Check if there are no more elements to iterate over.
   

   :param it: an iterator.
   

   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. zeek:id:: Broker::table_iterator_next
   :source-code: base/frameworks/broker/store.zeek 993 996

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`bool`

   Advance an iterator.
   

   :param it: an iterator.
   

   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. zeek:id:: Broker::table_iterator_value
   :source-code: base/frameworks/broker/store.zeek 998 1001

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`Broker::TableItem`

   Retrieve the data at an iterator's current position.
   

   :param it: an iterator.
   

   :returns: element in the collection that the iterator currently references.

.. zeek:id:: Broker::table_lookup
   :source-code: base/frameworks/broker/store.zeek 978 981

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Retrieve a value from a table.
   

   :param t: the table to query.
   

   :param key: the key to lookup.
   

   :returns: the value associated with the key.  If the key did not exist, then
            the optional field of the returned record is not set.

.. zeek:id:: Broker::table_remove
   :source-code: base/frameworks/broker/store.zeek 973 976

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Remove a key-value pair from a table.
   

   :param t: the table to modify.
   

   :param key: the key to remove from the table.
   

   :returns: the value associated with the key.  If the key did not exist, then
            the optional field of the returned record is not set.

.. zeek:id:: Broker::table_size
   :source-code: base/frameworks/broker/store.zeek 958 961

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`count`

   Get the number of elements within a table.
   

   :param t: the table to query.
   

   :returns: the number of elements in the table.

.. zeek:id:: Broker::vector_clear
   :source-code: base/frameworks/broker/store.zeek 1008 1011

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`bool`

   Remove all elements within a vector.
   

   :param v: the vector to clear.
   

   :returns: always true.

.. zeek:id:: Broker::vector_create
   :source-code: base/frameworks/broker/store.zeek 1003 1006

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`

   Create communication data of type "vector".

.. zeek:id:: Broker::vector_insert
   :source-code: base/frameworks/broker/store.zeek 1018 1021

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`bool`

   Insert an element into a vector at a particular position, possibly displacing
   existing elements (insertion always grows the size of the vector by one).
   

   :param v: the vector to modify.
   

   :param d: the element to insert.
   

   :param idx: the index at which to insert the data.  If it is greater than the
        current size of the vector, the element is inserted at the end.
   

   :returns: always true.

.. zeek:id:: Broker::vector_iterator
   :source-code: base/frameworks/broker/store.zeek 1038 1041

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::VectorIterator

   Create an iterator for a vector.  Note that this makes a copy of the vector
   internally to ensure the iterator is always valid.
   

   :param v: the vector to iterate over.
   

   :returns: an iterator.

.. zeek:id:: Broker::vector_iterator_last
   :source-code: base/frameworks/broker/store.zeek 1043 1046

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`bool`

   Check if there are no more elements to iterate over.
   

   :param it: an iterator.
   

   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. zeek:id:: Broker::vector_iterator_next
   :source-code: base/frameworks/broker/store.zeek 1048 1051

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`bool`

   Advance an iterator.
   

   :param it: an iterator.
   

   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. zeek:id:: Broker::vector_iterator_value
   :source-code: base/frameworks/broker/store.zeek 1053 1056

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`Broker::Data`

   Retrieve the data at an iterator's current position.
   

   :param it: an iterator.
   

   :returns: element in the collection that the iterator currently references.

.. zeek:id:: Broker::vector_lookup
   :source-code: base/frameworks/broker/store.zeek 1033 1036

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`

   Lookup an element in a vector at a particular position.
   

   :param v: the vector to query.
   

   :param idx: the index to lookup.
   

   :returns: the value at the index.  If the index was larger than any
            valid index, the optional field of the returned record is not set.

.. zeek:id:: Broker::vector_remove
   :source-code: base/frameworks/broker/store.zeek 1028 1031

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`

   Remove an element from a vector at a particular position.
   

   :param v: the vector to modify.
   

   :param idx: the index to remove.
   

   :returns: the value that was just evicted.  If the index was larger than any
            valid index, the optional field of the returned record is not set.

.. zeek:id:: Broker::vector_replace
   :source-code: base/frameworks/broker/store.zeek 1023 1026

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Replace an element in a vector at a particular position.
   

   :param v: the vector to modify.
   

   :param d: the element to insert.
   

   :param idx: the index to replace.
   

   :returns: the value that was just evicted.  If the index was larger than any
            valid index, the optional field of the returned record is not set.

.. zeek:id:: Broker::vector_size
   :source-code: base/frameworks/broker/store.zeek 1013 1016

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`count`

   Get the number of elements within a vector.
   

   :param v: the vector to query.
   

   :returns: the number of elements in the vector.


