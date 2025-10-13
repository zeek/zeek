:tocdepth: 3

base/frameworks/storage/async.zeek
==================================
.. zeek:namespace:: Storage::Async

Asynchronous operation methods for the storage framework.

:Namespace: Storage::Async
:Imports: :doc:`base/frameworks/storage/main.zeek </scripts/base/frameworks/storage/main.zeek>`

Summary
~~~~~~~
Functions
#########
=============================================================== ==============================================================================
:zeek:id:`Storage::Async::close_backend`: :zeek:type:`function` Closes an existing backend connection asynchronously.
:zeek:id:`Storage::Async::erase`: :zeek:type:`function`         Erases an entry from the backend asynchronously.
:zeek:id:`Storage::Async::get`: :zeek:type:`function`           Gets an entry from the backend asynchronously.
:zeek:id:`Storage::Async::open_backend`: :zeek:type:`function`  Opens a new backend connection based on a configuration object asynchronously.
:zeek:id:`Storage::Async::put`: :zeek:type:`function`           Inserts a new entry into a backend asynchronously.
=============================================================== ==============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Storage::Async::close_backend
   :source-code: base/frameworks/storage/async.zeek 91 97

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle) : :zeek:type:`Storage::OperationResult`

   Closes an existing backend connection asynchronously. This method must be
   called via a :zeek:see:`when` condition or an error will be returned.
   

   :param backend: A handle to a backend connection.
   

   :returns: A record containing the status of the operation and an optional error
            string for failures.

.. zeek:id:: Storage::Async::erase
   :source-code: base/frameworks/storage/async.zeek 120 126

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`

   Erases an entry from the backend asynchronously. This method must be called via
   a :zeek:see:`when` condition or an error will be returned.
   

   :param backend: A handle to a backend connection.
   

   :param key: The key to erase.
   

   :returns: A record containing the status of the operation and an optional error
            string for failures.

.. zeek:id:: Storage::Async::get
   :source-code: base/frameworks/storage/async.zeek 111 117

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`

   Gets an entry from the backend asynchronously. This method must be called via a
   :zeek:see:`when` condition or an error will be returned.
   

   :param backend: A handle to a backend connection.
   

   :param key: The key to look up.
   

   :returns: A record containing the status of the operation, an optional error
            string for failures, and an optional value for success. The value
            returned here will be of the type passed into
            :zeek:see:`Storage::Async::open_backend`.

.. zeek:id:: Storage::Async::open_backend
   :source-code: base/frameworks/storage/async.zeek 82 88

   :Type: :zeek:type:`function` (btype: :zeek:type:`Storage::Backend`, options: :zeek:type:`Storage::BackendOptions`, key_type: :zeek:type:`any`, val_type: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`

   Opens a new backend connection based on a configuration object asynchronously.
   This method must be called via a :zeek:see:`when` condition or an error will
   be returned.
   

   :param btype: A tag indicating what type of backend should be opened. These are
          defined by the backend plugins loaded.
   

   :param options: A record containing the configuration for the connection.
   

   :param key_type: The script-level type of keys stored in the backend. Used for
             validation of keys passed to other framework methods.
   

   :param val_type: The script-level type of keys stored in the backend. Used for
             validation of values passed to :zeek:see:`Storage::Async::put` as
             well as for type conversions for return values from
             :zeek:see:`Storage::Async::get`.
   

   :returns: A record containing the status of the operation, and either an error
            string on failure or a value on success. The value returned here will
            be an ``opaque of BackendHandle``.

.. zeek:id:: Storage::Async::put
   :source-code: base/frameworks/storage/async.zeek 100 108

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, args: :zeek:type:`Storage::PutArgs`) : :zeek:type:`Storage::OperationResult`

   Inserts a new entry into a backend asynchronously. This method must be called
   via a :zeek:see:`when` condition or an error will be returned.
   

   :param backend: A handle to a backend connection.
   

   :param args: A :zeek:see:`Storage::PutArgs` record containing the arguments for the
         operation.
   

   :returns: A record containing the status of the operation and an optional error
            string for failures.


