:tocdepth: 3

base/bif/storage-events.bif.zeek
================================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Storage

Events related to storage operations.

:Namespaces: GLOBAL, Storage

Summary
~~~~~~~
Events
######
====================================================== =============================================================================
:zeek:id:`Storage::backend_lost`: :zeek:type:`event`   May be generated when a backend connection is lost, both normally and
                                                       unexpectedly.
:zeek:id:`Storage::backend_opened`: :zeek:type:`event` Generated automatically when a new backend connection is opened successfully.
====================================================== =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: Storage::backend_lost
   :source-code: base/bif/storage-events.bif.zeek 34 34

   :Type: :zeek:type:`event` (tag: :zeek:type:`Storage::Backend`, options: :zeek:type:`any`, reason: :zeek:type:`string`)

   May be generated when a backend connection is lost, both normally and
   unexpectedly. This event depends on the backends implementing handling for
   it, and is not generated automatically by the storage framework.


   :param tag: A tag for one of the storage backends.


   :param options: A copy of the configuration options passed to
            :zeek:see:`Storage::Async::open_backend` or
            :zeek:see:`Storage::Sync::open_backend` when the backend was initially opened.


   :param reason: A string describing why the connection was lost.

   .. zeek:see:: Storage::backend_opened

.. zeek:id:: Storage::backend_opened
   :source-code: base/bif/storage-events.bif.zeek 18 18

   :Type: :zeek:type:`event` (tag: :zeek:type:`Storage::Backend`, options: :zeek:type:`any`)

   Generated automatically when a new backend connection is opened successfully.


   :param tag: A tag for one of the storage backends.


   :param options: A copy of the configuration options passed to
            :zeek:see:`Storage::Async::open_backend` or
            :zeek:see:`Storage::Sync::open_backend` when the backend was initially opened.

   .. zeek:see:: Storage::backend_lost


