:tocdepth: 3

base/bif/store.bif.zeek
=======================
.. bro:namespace:: Broker
.. bro:namespace:: GLOBAL

Functions to interface with broker's distributed data store.

:Namespaces: Broker, GLOBAL

Summary
~~~~~~~
Functions
#########
============================================================== =
:bro:id:`Broker::__append`: :bro:type:`function`               
:bro:id:`Broker::__clear`: :bro:type:`function`                
:bro:id:`Broker::__close`: :bro:type:`function`                
:bro:id:`Broker::__create_clone`: :bro:type:`function`         
:bro:id:`Broker::__create_master`: :bro:type:`function`        
:bro:id:`Broker::__decrement`: :bro:type:`function`            
:bro:id:`Broker::__erase`: :bro:type:`function`                
:bro:id:`Broker::__exists`: :bro:type:`function`               
:bro:id:`Broker::__get`: :bro:type:`function`                  
:bro:id:`Broker::__get_index_from_value`: :bro:type:`function` 
:bro:id:`Broker::__increment`: :bro:type:`function`            
:bro:id:`Broker::__insert_into_set`: :bro:type:`function`      
:bro:id:`Broker::__insert_into_table`: :bro:type:`function`    
:bro:id:`Broker::__is_closed`: :bro:type:`function`            
:bro:id:`Broker::__keys`: :bro:type:`function`                 
:bro:id:`Broker::__pop`: :bro:type:`function`                  
:bro:id:`Broker::__push`: :bro:type:`function`                 
:bro:id:`Broker::__put`: :bro:type:`function`                  
:bro:id:`Broker::__put_unique`: :bro:type:`function`           
:bro:id:`Broker::__remove_from`: :bro:type:`function`          
:bro:id:`Broker::__store_name`: :bro:type:`function`           
============================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: Broker::__append

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, s: :bro:type:`any`, e: :bro:type:`interval`) : :bro:type:`bool`


.. bro:id:: Broker::__clear

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store) : :bro:type:`bool`


.. bro:id:: Broker::__close

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store) : :bro:type:`bool`


.. bro:id:: Broker::__create_clone

   :Type: :bro:type:`function` (id: :bro:type:`string`, resync_interval: :bro:type:`interval`, stale_interval: :bro:type:`interval`, mutation_buffer_interval: :bro:type:`interval`) : :bro:type:`opaque` of Broker::Store


.. bro:id:: Broker::__create_master

   :Type: :bro:type:`function` (id: :bro:type:`string`, b: :bro:type:`Broker::BackendType`, options: :bro:type:`Broker::BackendOptions` :bro:attr:`&default` = ``[sqlite=[path=], rocksdb=[path=]]`` :bro:attr:`&optional`) : :bro:type:`opaque` of Broker::Store


.. bro:id:: Broker::__decrement

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, a: :bro:type:`any`, e: :bro:type:`interval`) : :bro:type:`bool`


.. bro:id:: Broker::__erase

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`) : :bro:type:`bool`


.. bro:id:: Broker::__exists

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`) : :bro:type:`Broker::QueryResult`


.. bro:id:: Broker::__get

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`) : :bro:type:`Broker::QueryResult`


.. bro:id:: Broker::__get_index_from_value

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, i: :bro:type:`any`) : :bro:type:`Broker::QueryResult`


.. bro:id:: Broker::__increment

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, a: :bro:type:`any`, e: :bro:type:`interval`) : :bro:type:`bool`


.. bro:id:: Broker::__insert_into_set

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, i: :bro:type:`any`, e: :bro:type:`interval`) : :bro:type:`bool`


.. bro:id:: Broker::__insert_into_table

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, i: :bro:type:`any`, v: :bro:type:`any`, e: :bro:type:`interval`) : :bro:type:`bool`


.. bro:id:: Broker::__is_closed

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store) : :bro:type:`bool`


.. bro:id:: Broker::__keys

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store) : :bro:type:`Broker::QueryResult`


.. bro:id:: Broker::__pop

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, e: :bro:type:`interval`) : :bro:type:`bool`


.. bro:id:: Broker::__push

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, v: :bro:type:`any`, e: :bro:type:`interval`) : :bro:type:`bool`


.. bro:id:: Broker::__put

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, v: :bro:type:`any`, e: :bro:type:`interval`) : :bro:type:`bool`


.. bro:id:: Broker::__put_unique

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, v: :bro:type:`any`, e: :bro:type:`interval`) : :bro:type:`Broker::QueryResult`


.. bro:id:: Broker::__remove_from

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store, k: :bro:type:`any`, i: :bro:type:`any`, e: :bro:type:`interval`) : :bro:type:`bool`


.. bro:id:: Broker::__store_name

   :Type: :bro:type:`function` (h: :bro:type:`opaque` of Broker::Store) : :bro:type:`string`



