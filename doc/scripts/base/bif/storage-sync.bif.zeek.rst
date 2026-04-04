:tocdepth: 3

base/bif/storage-sync.bif.zeek
==============================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Storage::Sync

Functions related to synchronous storage operations.

:Namespaces: GLOBAL, Storage::Sync

Summary
~~~~~~~
Functions
#########
================================================================ =
:zeek:id:`Storage::Sync::__close_backend`: :zeek:type:`function`
:zeek:id:`Storage::Sync::__erase`: :zeek:type:`function`
:zeek:id:`Storage::Sync::__get`: :zeek:type:`function`
:zeek:id:`Storage::Sync::__open_backend`: :zeek:type:`function`
:zeek:id:`Storage::Sync::__put`: :zeek:type:`function`
================================================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Storage::Sync::__close_backend
   :source-code: base/bif/storage-sync.bif.zeek 14 14

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle) : :zeek:type:`Storage::OperationResult`


.. zeek:id:: Storage::Sync::__erase
   :source-code: base/bif/storage-sync.bif.zeek 23 23

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`


.. zeek:id:: Storage::Sync::__get
   :source-code: base/bif/storage-sync.bif.zeek 20 20

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`


.. zeek:id:: Storage::Sync::__open_backend
   :source-code: base/bif/storage-sync.bif.zeek 11 11

   :Type: :zeek:type:`function` (btype: :zeek:type:`Storage::Backend`, options: :zeek:type:`any`, key_type: :zeek:type:`any`, val_type: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`


.. zeek:id:: Storage::Sync::__put
   :source-code: base/bif/storage-sync.bif.zeek 17 17

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`, value: :zeek:type:`any`, overwrite: :zeek:type:`bool`, expire_time: :zeek:type:`interval`) : :zeek:type:`Storage::OperationResult`



