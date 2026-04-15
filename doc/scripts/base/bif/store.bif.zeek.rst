:tocdepth: 3

base/bif/store.bif.zeek
=======================
.. zeek:namespace:: Broker
.. zeek:namespace:: GLOBAL

Functions to interface with broker's distributed data store.

:Namespaces: Broker, GLOBAL

Summary
~~~~~~~
Functions
#########
========================================================================================== =
:zeek:id:`Broker::__append`: :zeek:type:`function`
:zeek:id:`Broker::__clear`: :zeek:type:`function`
:zeek:id:`Broker::__close`: :zeek:type:`function`
:zeek:id:`Broker::__create_clone`: :zeek:type:`function` :zeek:attr:`&deprecated` = *...*
:zeek:id:`Broker::__create_master`: :zeek:type:`function` :zeek:attr:`&deprecated` = *...*
:zeek:id:`Broker::__decrement`: :zeek:type:`function`
:zeek:id:`Broker::__erase`: :zeek:type:`function`
:zeek:id:`Broker::__exists`: :zeek:type:`function`
:zeek:id:`Broker::__get`: :zeek:type:`function`
:zeek:id:`Broker::__get_index_from_value`: :zeek:type:`function`
:zeek:id:`Broker::__increment`: :zeek:type:`function`
:zeek:id:`Broker::__insert_into_set`: :zeek:type:`function`
:zeek:id:`Broker::__insert_into_table`: :zeek:type:`function`
:zeek:id:`Broker::__is_closed`: :zeek:type:`function`
:zeek:id:`Broker::__keys`: :zeek:type:`function`
:zeek:id:`Broker::__pop`: :zeek:type:`function`
:zeek:id:`Broker::__push`: :zeek:type:`function`
:zeek:id:`Broker::__put`: :zeek:type:`function`
:zeek:id:`Broker::__put_unique`: :zeek:type:`function`
:zeek:id:`Broker::__remove_from`: :zeek:type:`function`
:zeek:id:`Broker::__store_name`: :zeek:type:`function`
========================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Broker::__append
   :source-code: base/bif/store.bif.zeek 66 66

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, s: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__clear
   :source-code: base/bif/store.bif.zeek 84 84

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`bool`


.. zeek:id:: Broker::__close
   :source-code: base/bif/store.bif.zeek 33 33

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`bool`


.. zeek:id:: Broker::__create_clone
   :source-code: base/bif/store.bif.zeek 26 26

   :Type: :zeek:type:`function` (id: :zeek:type:`string`, resync_interval: :zeek:type:`interval`, stale_interval: :zeek:type:`interval`, mutation_buffer_interval: :zeek:type:`interval`) : :zeek:type:`opaque` of Broker::Store
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in v9.1. Broker stores are deprecated."*


.. zeek:id:: Broker::__create_master
   :source-code: base/bif/store.bif.zeek 22 22

   :Type: :zeek:type:`function` (id: :zeek:type:`string`, b: :zeek:type:`Broker::BackendType`, options: :zeek:type:`Broker::BackendOptions` :zeek:attr:`&default` = *[sqlite=[path=, synchronous=<uninitialized>, journal_mode=<uninitialized>, failure_mode=Broker::SQLITE_FAILURE_MODE_FAIL, integrity_check=F]]* :zeek:attr:`&optional`) : :zeek:type:`opaque` of Broker::Store
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in v9.1. Broker stores are deprecated."*


.. zeek:id:: Broker::__decrement
   :source-code: base/bif/store.bif.zeek 63 63

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, a: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__erase
   :source-code: base/bif/store.bif.zeek 57 57

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__exists
   :source-code: base/bif/store.bif.zeek 39 39

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`) : :zeek:type:`Broker::QueryResult`


.. zeek:id:: Broker::__get
   :source-code: base/bif/store.bif.zeek 42 42

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`) : :zeek:type:`Broker::QueryResult`


.. zeek:id:: Broker::__get_index_from_value
   :source-code: base/bif/store.bif.zeek 48 48

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`) : :zeek:type:`Broker::QueryResult`


.. zeek:id:: Broker::__increment
   :source-code: base/bif/store.bif.zeek 60 60

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, a: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__insert_into_set
   :source-code: base/bif/store.bif.zeek 69 69

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__insert_into_table
   :source-code: base/bif/store.bif.zeek 72 72

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__is_closed
   :source-code: base/bif/store.bif.zeek 30 30

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`bool`


.. zeek:id:: Broker::__keys
   :source-code: base/bif/store.bif.zeek 51 51

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`Broker::QueryResult`


.. zeek:id:: Broker::__pop
   :source-code: base/bif/store.bif.zeek 81 81

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__push
   :source-code: base/bif/store.bif.zeek 78 78

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__put
   :source-code: base/bif/store.bif.zeek 54 54

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__put_unique
   :source-code: base/bif/store.bif.zeek 45 45

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`Broker::QueryResult`


.. zeek:id:: Broker::__remove_from
   :source-code: base/bif/store.bif.zeek 75 75

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__store_name
   :source-code: base/bif/store.bif.zeek 36 36

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`string`



