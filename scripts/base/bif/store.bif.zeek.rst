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
================================================================ =
:zeek:id:`Broker::__append`: :zeek:type:`function`               
:zeek:id:`Broker::__clear`: :zeek:type:`function`                
:zeek:id:`Broker::__close`: :zeek:type:`function`                
:zeek:id:`Broker::__create_clone`: :zeek:type:`function`         
:zeek:id:`Broker::__create_master`: :zeek:type:`function`        
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
================================================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Broker::__append

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, s: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__clear

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`bool`


.. zeek:id:: Broker::__close

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`bool`


.. zeek:id:: Broker::__create_clone

   :Type: :zeek:type:`function` (id: :zeek:type:`string`, resync_interval: :zeek:type:`interval`, stale_interval: :zeek:type:`interval`, mutation_buffer_interval: :zeek:type:`interval`) : :zeek:type:`opaque` of Broker::Store


.. zeek:id:: Broker::__create_master

   :Type: :zeek:type:`function` (id: :zeek:type:`string`, b: :zeek:type:`Broker::BackendType`, options: :zeek:type:`Broker::BackendOptions` :zeek:attr:`&default` = *[sqlite=[path=], rocksdb=[path=]]* :zeek:attr:`&optional`) : :zeek:type:`opaque` of Broker::Store


.. zeek:id:: Broker::__decrement

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, a: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__erase

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__exists

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`) : :zeek:type:`Broker::QueryResult`


.. zeek:id:: Broker::__get

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`) : :zeek:type:`Broker::QueryResult`


.. zeek:id:: Broker::__get_index_from_value

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`) : :zeek:type:`Broker::QueryResult`


.. zeek:id:: Broker::__increment

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, a: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__insert_into_set

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__insert_into_table

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__is_closed

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`bool`


.. zeek:id:: Broker::__keys

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`Broker::QueryResult`


.. zeek:id:: Broker::__pop

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__push

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__put

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__put_unique

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, v: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`Broker::QueryResult`


.. zeek:id:: Broker::__remove_from

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store, k: :zeek:type:`any`, i: :zeek:type:`any`, e: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__store_name

   :Type: :zeek:type:`function` (h: :zeek:type:`opaque` of Broker::Store) : :zeek:type:`string`



