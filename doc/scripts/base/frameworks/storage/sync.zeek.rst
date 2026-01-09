:tocdepth: 3

base/frameworks/storage/sync.zeek
=================================
.. zeek:namespace:: Storage::Sync

Synchronous operation methods for the storage framework.

:Namespace: Storage::Sync
:Imports: :doc:`base/frameworks/storage/main.zeek </scripts/base/frameworks/storage/main.zeek>`

Summary
~~~~~~~
Functions
#########
============================================================== ===============================================================
:zeek:id:`Storage::Sync::close_backend`: :zeek:type:`function` Closes an existing backend connection.
:zeek:id:`Storage::Sync::erase`: :zeek:type:`function`         Erases an entry from the backend.
:zeek:id:`Storage::Sync::get`: :zeek:type:`function`           Gets an entry from the backend.
:zeek:id:`Storage::Sync::open_backend`: :zeek:type:`function`  Opens a new backend connection based on a configuration object.
:zeek:id:`Storage::Sync::put`: :zeek:type:`function`           Inserts a new entry into a backend.
============================================================== ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Storage::Sync::close_backend
   :source-code: base/frameworks/storage/sync.zeek 82 85

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle) : :zeek:type:`Storage::OperationResult`

   Closes an existing backend connection.


   :param backend: A handle to a backend connection.


   :returns: A record containing the status of the operation and an optional error
            string for failures.

.. zeek:id:: Storage::Sync::erase
   :source-code: base/frameworks/storage/sync.zeek 101 104

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`

   Erases an entry from the backend.


   :param backend: A handle to a backend connection.


   :param key: The key to erase.


   :returns: A record containing the status of the operation and an optional error
            string for failures.

.. zeek:id:: Storage::Sync::get
   :source-code: base/frameworks/storage/sync.zeek 95 98

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`

   Gets an entry from the backend.


   :param backend: A handle to a backend connection.


   :param key: The key to look up.


   :returns: A record containing the status of the operation, an optional error
            string for failures, and an optional value for success. The value
            returned here will be of the type passed into
            :zeek:see:`Storage::Sync::open_backend`.

.. zeek:id:: Storage::Sync::open_backend
   :source-code: base/frameworks/storage/sync.zeek 76 79

   :Type: :zeek:type:`function` (btype: :zeek:type:`Storage::Backend`, options: :zeek:type:`Storage::BackendOptions`, key_type: :zeek:type:`any`, val_type: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`

   Opens a new backend connection based on a configuration object.


   :param btype: A tag indicating what type of backend should be opened. These are
          defined by the backend plugins loaded.


   :param options: A record containing the configuration for the connection.


   :param key_type: The script-level type of keys stored in the backend. Used for
             validation of keys passed to other framework methods.


   :param val_type: The script-level type of keys stored in the backend. Used for
             validation of values passed to :zeek:see:`Storage::Sync::put` as well
             as for type conversions for return values from
             :zeek:see:`Storage::Sync::get`.


   :returns: A record containing the status of the operation, and either an error
            string on failure or a value on success. The value returned here will
            be an ``opaque of BackendHandle``.

.. zeek:id:: Storage::Sync::put
   :source-code: base/frameworks/storage/sync.zeek 88 92

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, args: :zeek:type:`Storage::PutArgs`) : :zeek:type:`Storage::OperationResult`

   Inserts a new entry into a backend.


   :param backend: A handle to a backend connection.


   :param args: A :zeek:see:`Storage::PutArgs` record containing the arguments for the
         operation.


   :returns: A record containing the status of the operation and an optional error
            string for failures.


