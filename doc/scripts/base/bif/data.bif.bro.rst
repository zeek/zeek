:tocdepth: 3

base/bif/data.bif.bro
=====================
.. bro:namespace:: Broker
.. bro:namespace:: GLOBAL

Functions for inspecting and manipulating broker data.

:Namespaces: Broker, GLOBAL

Summary
~~~~~~~
Types
#####
============================================== ====================================================================
:bro:type:`Broker::DataType`: :bro:type:`enum` Enumerates the possible types that :bro:see:`Broker::Data` may be in
                                               terms of Bro data types.
============================================== ====================================================================

Functions
#########
=============================================================== =
:bro:id:`Broker::__data`: :bro:type:`function`                  
:bro:id:`Broker::__data_type`: :bro:type:`function`             
:bro:id:`Broker::__record_assign`: :bro:type:`function`         
:bro:id:`Broker::__record_create`: :bro:type:`function`         
:bro:id:`Broker::__record_iterator`: :bro:type:`function`       
:bro:id:`Broker::__record_iterator_last`: :bro:type:`function`  
:bro:id:`Broker::__record_iterator_next`: :bro:type:`function`  
:bro:id:`Broker::__record_iterator_value`: :bro:type:`function` 
:bro:id:`Broker::__record_lookup`: :bro:type:`function`         
:bro:id:`Broker::__record_size`: :bro:type:`function`           
:bro:id:`Broker::__set_clear`: :bro:type:`function`             
:bro:id:`Broker::__set_contains`: :bro:type:`function`          
:bro:id:`Broker::__set_create`: :bro:type:`function`            
:bro:id:`Broker::__set_insert`: :bro:type:`function`            
:bro:id:`Broker::__set_iterator`: :bro:type:`function`          
:bro:id:`Broker::__set_iterator_last`: :bro:type:`function`     
:bro:id:`Broker::__set_iterator_next`: :bro:type:`function`     
:bro:id:`Broker::__set_iterator_value`: :bro:type:`function`    
:bro:id:`Broker::__set_remove`: :bro:type:`function`            
:bro:id:`Broker::__set_size`: :bro:type:`function`              
:bro:id:`Broker::__table_clear`: :bro:type:`function`           
:bro:id:`Broker::__table_contains`: :bro:type:`function`        
:bro:id:`Broker::__table_create`: :bro:type:`function`          
:bro:id:`Broker::__table_insert`: :bro:type:`function`          
:bro:id:`Broker::__table_iterator`: :bro:type:`function`        
:bro:id:`Broker::__table_iterator_last`: :bro:type:`function`   
:bro:id:`Broker::__table_iterator_next`: :bro:type:`function`   
:bro:id:`Broker::__table_iterator_value`: :bro:type:`function`  
:bro:id:`Broker::__table_lookup`: :bro:type:`function`          
:bro:id:`Broker::__table_remove`: :bro:type:`function`          
:bro:id:`Broker::__table_size`: :bro:type:`function`            
:bro:id:`Broker::__vector_clear`: :bro:type:`function`          
:bro:id:`Broker::__vector_create`: :bro:type:`function`         
:bro:id:`Broker::__vector_insert`: :bro:type:`function`         
:bro:id:`Broker::__vector_iterator`: :bro:type:`function`       
:bro:id:`Broker::__vector_iterator_last`: :bro:type:`function`  
:bro:id:`Broker::__vector_iterator_next`: :bro:type:`function`  
:bro:id:`Broker::__vector_iterator_value`: :bro:type:`function` 
:bro:id:`Broker::__vector_lookup`: :bro:type:`function`         
:bro:id:`Broker::__vector_remove`: :bro:type:`function`         
:bro:id:`Broker::__vector_replace`: :bro:type:`function`        
:bro:id:`Broker::__vector_size`: :bro:type:`function`           
=============================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: Broker::DataType

   :Type: :bro:type:`enum`

      .. bro:enum:: Broker::NONE Broker::DataType

      .. bro:enum:: Broker::BOOL Broker::DataType

      .. bro:enum:: Broker::INT Broker::DataType

      .. bro:enum:: Broker::COUNT Broker::DataType

      .. bro:enum:: Broker::DOUBLE Broker::DataType

      .. bro:enum:: Broker::STRING Broker::DataType

      .. bro:enum:: Broker::ADDR Broker::DataType

      .. bro:enum:: Broker::SUBNET Broker::DataType

      .. bro:enum:: Broker::PORT Broker::DataType

      .. bro:enum:: Broker::TIME Broker::DataType

      .. bro:enum:: Broker::INTERVAL Broker::DataType

      .. bro:enum:: Broker::ENUM Broker::DataType

      .. bro:enum:: Broker::SET Broker::DataType

      .. bro:enum:: Broker::TABLE Broker::DataType

      .. bro:enum:: Broker::VECTOR Broker::DataType

   Enumerates the possible types that :bro:see:`Broker::Data` may be in
   terms of Bro data types.

Functions
#########
.. bro:id:: Broker::__data

   :Type: :bro:type:`function` (d: :bro:type:`any`) : :bro:type:`Broker::Data`


.. bro:id:: Broker::__data_type

   :Type: :bro:type:`function` (d: :bro:type:`Broker::Data`) : :bro:type:`Broker::DataType`


.. bro:id:: Broker::__record_assign

   :Type: :bro:type:`function` (r: :bro:type:`Broker::Data`, idx: :bro:type:`count`, d: :bro:type:`any`) : :bro:type:`bool`


.. bro:id:: Broker::__record_create

   :Type: :bro:type:`function` (sz: :bro:type:`count`) : :bro:type:`Broker::Data`


.. bro:id:: Broker::__record_iterator

   :Type: :bro:type:`function` (r: :bro:type:`Broker::Data`) : :bro:type:`opaque` of Broker::RecordIterator


.. bro:id:: Broker::__record_iterator_last

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::RecordIterator) : :bro:type:`bool`


.. bro:id:: Broker::__record_iterator_next

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::RecordIterator) : :bro:type:`bool`


.. bro:id:: Broker::__record_iterator_value

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::RecordIterator) : :bro:type:`Broker::Data`


.. bro:id:: Broker::__record_lookup

   :Type: :bro:type:`function` (r: :bro:type:`Broker::Data`, idx: :bro:type:`count`) : :bro:type:`Broker::Data`


.. bro:id:: Broker::__record_size

   :Type: :bro:type:`function` (r: :bro:type:`Broker::Data`) : :bro:type:`count`


.. bro:id:: Broker::__set_clear

   :Type: :bro:type:`function` (s: :bro:type:`Broker::Data`) : :bro:type:`bool`


.. bro:id:: Broker::__set_contains

   :Type: :bro:type:`function` (s: :bro:type:`Broker::Data`, key: :bro:type:`any`) : :bro:type:`bool`


.. bro:id:: Broker::__set_create

   :Type: :bro:type:`function` () : :bro:type:`Broker::Data`


.. bro:id:: Broker::__set_insert

   :Type: :bro:type:`function` (s: :bro:type:`Broker::Data`, key: :bro:type:`any`) : :bro:type:`bool`


.. bro:id:: Broker::__set_iterator

   :Type: :bro:type:`function` (s: :bro:type:`Broker::Data`) : :bro:type:`opaque` of Broker::SetIterator


.. bro:id:: Broker::__set_iterator_last

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::SetIterator) : :bro:type:`bool`


.. bro:id:: Broker::__set_iterator_next

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::SetIterator) : :bro:type:`bool`


.. bro:id:: Broker::__set_iterator_value

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::SetIterator) : :bro:type:`Broker::Data`


.. bro:id:: Broker::__set_remove

   :Type: :bro:type:`function` (s: :bro:type:`Broker::Data`, key: :bro:type:`any`) : :bro:type:`bool`


.. bro:id:: Broker::__set_size

   :Type: :bro:type:`function` (s: :bro:type:`Broker::Data`) : :bro:type:`count`


.. bro:id:: Broker::__table_clear

   :Type: :bro:type:`function` (t: :bro:type:`Broker::Data`) : :bro:type:`bool`


.. bro:id:: Broker::__table_contains

   :Type: :bro:type:`function` (t: :bro:type:`Broker::Data`, key: :bro:type:`any`) : :bro:type:`bool`


.. bro:id:: Broker::__table_create

   :Type: :bro:type:`function` () : :bro:type:`Broker::Data`


.. bro:id:: Broker::__table_insert

   :Type: :bro:type:`function` (t: :bro:type:`Broker::Data`, key: :bro:type:`any`, val: :bro:type:`any`) : :bro:type:`Broker::Data`


.. bro:id:: Broker::__table_iterator

   :Type: :bro:type:`function` (t: :bro:type:`Broker::Data`) : :bro:type:`opaque` of Broker::TableIterator


.. bro:id:: Broker::__table_iterator_last

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::TableIterator) : :bro:type:`bool`


.. bro:id:: Broker::__table_iterator_next

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::TableIterator) : :bro:type:`bool`


.. bro:id:: Broker::__table_iterator_value

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::TableIterator) : :bro:type:`Broker::TableItem`


.. bro:id:: Broker::__table_lookup

   :Type: :bro:type:`function` (t: :bro:type:`Broker::Data`, key: :bro:type:`any`) : :bro:type:`Broker::Data`


.. bro:id:: Broker::__table_remove

   :Type: :bro:type:`function` (t: :bro:type:`Broker::Data`, key: :bro:type:`any`) : :bro:type:`Broker::Data`


.. bro:id:: Broker::__table_size

   :Type: :bro:type:`function` (t: :bro:type:`Broker::Data`) : :bro:type:`count`


.. bro:id:: Broker::__vector_clear

   :Type: :bro:type:`function` (v: :bro:type:`Broker::Data`) : :bro:type:`bool`


.. bro:id:: Broker::__vector_create

   :Type: :bro:type:`function` () : :bro:type:`Broker::Data`


.. bro:id:: Broker::__vector_insert

   :Type: :bro:type:`function` (v: :bro:type:`Broker::Data`, idx: :bro:type:`count`, d: :bro:type:`any`) : :bro:type:`bool`


.. bro:id:: Broker::__vector_iterator

   :Type: :bro:type:`function` (v: :bro:type:`Broker::Data`) : :bro:type:`opaque` of Broker::VectorIterator


.. bro:id:: Broker::__vector_iterator_last

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::VectorIterator) : :bro:type:`bool`


.. bro:id:: Broker::__vector_iterator_next

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::VectorIterator) : :bro:type:`bool`


.. bro:id:: Broker::__vector_iterator_value

   :Type: :bro:type:`function` (it: :bro:type:`opaque` of Broker::VectorIterator) : :bro:type:`Broker::Data`


.. bro:id:: Broker::__vector_lookup

   :Type: :bro:type:`function` (v: :bro:type:`Broker::Data`, idx: :bro:type:`count`) : :bro:type:`Broker::Data`


.. bro:id:: Broker::__vector_remove

   :Type: :bro:type:`function` (v: :bro:type:`Broker::Data`, idx: :bro:type:`count`) : :bro:type:`Broker::Data`


.. bro:id:: Broker::__vector_replace

   :Type: :bro:type:`function` (v: :bro:type:`Broker::Data`, idx: :bro:type:`count`, d: :bro:type:`any`) : :bro:type:`Broker::Data`


.. bro:id:: Broker::__vector_size

   :Type: :bro:type:`function` (v: :bro:type:`Broker::Data`) : :bro:type:`count`



