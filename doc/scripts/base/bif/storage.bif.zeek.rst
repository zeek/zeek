:tocdepth: 3

base/bif/storage.bif.zeek
=========================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Storage

Functions related to general storage operations. These are not specific to async or sync.

:Namespaces: GLOBAL, Storage

Summary
~~~~~~~
Functions
#########
========================================================= =======================================================================
:zeek:id:`Storage::is_forced_sync`: :zeek:type:`function` Checks whether a storage backend was opened in forced-synchronous mode.
:zeek:id:`Storage::is_open`: :zeek:type:`function`        Checks whether a storage backend is open.
========================================================= =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Storage::is_forced_sync
   :source-code: base/bif/storage.bif.zeek 26 26

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle) : :zeek:type:`bool`

   Checks whether a storage backend was opened in forced-synchronous mode.
   

   :param backend: A handle to the backend to check.
   

   :returns: T if the forced_synchronous option was set to T, F otherwise or if the
            handle is invalid.

.. zeek:id:: Storage::is_open
   :source-code: base/bif/storage.bif.zeek 17 17

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle) : :zeek:type:`bool`

   Checks whether a storage backend is open.
   

   :param backend: A handle to the backed to check.
   

   :returns: T if the backend is open, F if the backend is not open or if the handle
            is invalid.


