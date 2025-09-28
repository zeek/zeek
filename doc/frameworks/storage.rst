.. _framework-storage:

.. versionadded:: 7.2

=================
Storage Framework
=================

The storage framework provides a plugin-based system for short- and long-term storage of
data, accessible from Zeek script-land. This is not packet data itself, but data artifacts
generated from the packet data. It has interchangeable asynchronous and synchronous
modes. The framework provides just a simple key-value store, using Zeek values as the keys
to store and lookup data.

This chapter gives an overview of the storage framework, plus examples of using it. For
more examples, see the test cases in ``testing/btest/scripts/base/frameworks/storage`` and
an example storage plugin in ``testing/btest/plugin/storage-src``.

Terminology
===========

Zeek's storage framework uses two main components:

  Backend
    A backend plugin provides access to a storage system. Backends can be network-based
    storage systems such as Redis, on-disk database systems such as SQLite, etc. Backend
    plugins can define script-level records for configuring them when they're opened. Zeek
    provides backends for Redis and SQLite by default, but others may be implemented as
    external packages.

  Serializer
    A serializer plugin provides a mechanism for converting data from Zeek scripts into
    formats that backends can use.  Serializers are intended to be agnostic to
    backends. They convert between Zeek values and opaque byte buffers, and backends
    should be able to handle the result of any individual serializer. Zeek provides a JSON
    serializer by default, but others may be implemented as external packages.

Asynchronous Mode vs Synchronous Mode
=====================================

Storage backends support both asynchronous and synchronous modes. The difference between
using the two modes is that asynchronous calls must be used as part of :zeek:see:`when`
statements, whereas synchronous calls can be used either with ``when`` statements or
called directly. Synchronous functions will block until the backend returns
data. Otherwise, all of the arguments and return values are the same between them. They
are split between two script-level modules: :zeek:see:`Storage::Async` loaded from
``base/frameworks/storage/async`` and :zeek:see:`Storage::Sync` loaded from
``base/frameworks/storage/sync``.

When reading pcap data via the ``-r`` Zeek argument, all backends operate in a synchronous
manner internally to ensure that Zeek's timers run correctly. Regardless of this behavior,
asynchronous functions are required to be used with the ``when`` statement, but they'll
essentially be translated to synchronous calls.

Using the Storage Framework
===========================

All of the examples below use the SQLite backend. Usage of other backends follows the same
model. Switching the examples to a different backend involves only using a different tag
and options record with the :zeek:see:`Storage::Async::open_backend`/
:zeek:see:`Storage::Sync::open_backend` functions.

Operation Return Values
-----------------------

All backend methods return a record of type :zeek:see:`Storage::OperationResult`. This
record contains a code that indicates the result of the operation. For failures, backends
may provide more details in the optional error message. The record will also contain data
for operations that return values, namely ``open_backend`` or ``get``.
:zeek:see:`Storage::ReturnCode` contains all of the codes that can be returned from the
various operations. Not all codes are valid for all operations.
:zeek:see:`Storage::ReturnCode` can be redefined by backends to add new backend-specific
statuscodes as needed.

.. _storage-opening-closing:

Opening and Closing a Backend
-----------------------------

Opening a backend starts with defining a set of options for that backend. The
:zeek:see:`Storage::BackendOptions` is defined with some fields by default, but loading a
policy for a specific backend type may add new fields to it. In the example below, we
loaded the SQLite policy, which adds a new ``sqlite`` field with additional options. These
options are filled in to denote where to store the sqlite database file and what table to
use. This allows users to separate different instances of a backend from each other in a
single database file.

The script then sets a serializer. The storage framework sets this to the JSON
(:zeek:see:`Storage::STORAGE_SERIALIZER_JSON`) serializer by default, but setting it
explicitly is included below as an example.

Calling :zeek:see:`Storage::Sync::open_backend` instantiates a backend connection. As
described above, ``open_backend`` returns a :zeek:see:`Storage::OperationResult`. On
success, it stores the handle to the backend in the ``value`` field of the result
record. We check the ``code`` field as well to make sure the operation succeeded.  Backend
handles can be stored in global values just like any other value. They can be opened
during startup, such as in a :zeek:see:`zeek_init` event handler, and reused throughout
the runtime of Zeek. When a backend is successfully opened, a
:zeek:see:`Storage::backend_opened` event will be emitted.

The two type arguments to ``open_backend`` define the script-level types for keys and
values. Attempting to use other types with the backend results in
:zeek:see:`Storage::KEY_TYPE_MISMATCH` errors.

Lastly, we call :zeek:see:`Storage::Sync::close_backend` to close the backend before
exiting. When a backend is successfully closed, a :zeek:see:`Storage::backend_lost` event
will be emitted.

.. code-block:: zeek

  @load base/frameworks/storage/sync
  @load policy/frameworks/storage/backend/sqlite

  local backend_opts: Storage::BackendOptions;
  local backend: Storage::BackendHandle;

  # Loading the sqlite policy adds this field to the options record.
  opts$sqlite = [$database_path="test.sqlite", $table_name="testing"];

  # This is the default, but is shown here for how to set it.
  opts$serializer = Storage::STORAGE_SERIALIZER_JSON;

  local res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts, string, string);
  if ( res$code == Storage::SUCCESS )
    backend = res$value;

  res = Storage::Sync::close_backend(backend);

Storing, Retrieving, and Erasing Data
-------------------------------------

The true point of the storage framework is to store and retrieve data. This example shows
making synchronous calls to add a new key/value pair to a backend, retrieve it, and erase
the entry associated with the key. This assumes that the ``backend`` variable used below
points to an opened backend handle. The idea is that users do not need to worry about the
underlying backend implementation. In terms of Zeek's script-layer API, SQLite, Redis, or
other backends should behave identically.

First, we make a call to :zeek:see:`Storage::Sync::put`, passing a key and a value to be
stored. These must be of the same types that were passed in the arguments to
``open_backend``, as described in the :ref:`earlier section <storage-opening-closing>`.
The arguments passed into ``put`` are contained in a record of type
:zeek:see:`Storage::PutArgs`. See the documentation for that type for descriptions of the
fields available. In this case, we specify a key and a value plus an expiration time. This
expiration time indicates when the data should be automatically removed from the
backend. We check the result value, and print the error string and return if the operation
failed.

Next, we attempt to retrieve the same key from the backend. Assuming that the key hasn't
been erased, either manually or via expiration, the value is returned in the ``value``
field of the result record. If the key has been removed already, the backend should return
a :zeek:see:`Storage::KEY_NOT_FOUND` code.

Finally, we manually attempt to erase the key. This will remove the key/value pair from
the store, assuming that it hasn't already been removed manually or via expiration. Same
as with ``get``, :zeek:see:`Storage::KEY_NOT_FOUND` should be returned if the key doesn't
exist.

.. code-block:: zeek

  local res = Storage::Sync::put(backend, [$key="abc", $value="def", $expire_time=45sec]);
  if ( res$code != Storage::SUCCESS )
    {
    print(res$error_str);
    return;
    }

  res = Storage::Sync::get(backend, "abc");
  if ( res$code != Storage::SUCCESS )
    {
    print(res$error_str);
    return;
    }

  res = Storage:Sync::erase(backend, "abc");
  if ( res$code != Storage::SUCCESS )
    {
    print(res$error_str);
    return;
    }

Events
======

Two events exist for the storage framework: :zeek:see:`Storage::backend_lost` and
:zeek:see:`Storage::backend_opened`. Both events were mentioned in the :ref:`example of
opening and closing a backend <storage-opening-closing>`, but an additional point needs to
be made about the :zeek:see:`Storage::backend_lost` event. This event is also raised when
a connection is lost unexpectedly. This gives users information about connection failures,
as well an opportunity to handle those failures by reconnecting.

Notes for Built-in Backends
===========================

Redis
-----

- The Redis backend requires the ``hiredis`` library to installed on the system in order
  to build. At least version 1.1.0 (Released Nov 2022) is required.

- Redis server version 6.2.0 or later (or a third-party server implementing the equivalent
  level of the Redis API) is required. This is due to some API features the backend uses
  not being implemented until that version.

SQLite
------

- The default batch of pragmas in :zeek:see:`Storage::Backend::SQLite::Options` set
  ``journal_mode`` to ``WAL``. ``WAL`` mode does not work over network filesystems. If
  this mode is used, the database file must be stored on the same computer as all of the
  Zeek processes opening it. See the documentation in https://www.sqlite.org/wal.html for
  more information.

- Usage of in-memory databases (i.e. passing ``:memory:`` as the database path) will
  result in data not being synced between nodes. Each process will open its own database
  within that process's memory space.
