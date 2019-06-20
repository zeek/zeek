:tocdepth: 3

base/bif/data.bif.zeek
======================
.. zeek:namespace:: Broker
.. zeek:namespace:: GLOBAL

Functions for inspecting and manipulating broker data.

:Namespaces: Broker, GLOBAL

Summary
~~~~~~~
Types
#####
================================================ =====================================================================
:zeek:type:`Broker::DataType`: :zeek:type:`enum` Enumerates the possible types that :zeek:see:`Broker::Data` may be in
                                                 terms of Zeek data types.
================================================ =====================================================================

Functions
#########
============================================================================== =
:zeek:id:`Broker::__data`: :zeek:type:`function`                               
:zeek:id:`Broker::__data_type`: :zeek:type:`function`                          
:zeek:id:`Broker::__opaque_clone_through_serialization`: :zeek:type:`function` 
:zeek:id:`Broker::__record_assign`: :zeek:type:`function`                      
:zeek:id:`Broker::__record_create`: :zeek:type:`function`                      
:zeek:id:`Broker::__record_iterator`: :zeek:type:`function`                    
:zeek:id:`Broker::__record_iterator_last`: :zeek:type:`function`               
:zeek:id:`Broker::__record_iterator_next`: :zeek:type:`function`               
:zeek:id:`Broker::__record_iterator_value`: :zeek:type:`function`              
:zeek:id:`Broker::__record_lookup`: :zeek:type:`function`                      
:zeek:id:`Broker::__record_size`: :zeek:type:`function`                        
:zeek:id:`Broker::__set_clear`: :zeek:type:`function`                          
:zeek:id:`Broker::__set_contains`: :zeek:type:`function`                       
:zeek:id:`Broker::__set_create`: :zeek:type:`function`                         
:zeek:id:`Broker::__set_insert`: :zeek:type:`function`                         
:zeek:id:`Broker::__set_iterator`: :zeek:type:`function`                       
:zeek:id:`Broker::__set_iterator_last`: :zeek:type:`function`                  
:zeek:id:`Broker::__set_iterator_next`: :zeek:type:`function`                  
:zeek:id:`Broker::__set_iterator_value`: :zeek:type:`function`                 
:zeek:id:`Broker::__set_remove`: :zeek:type:`function`                         
:zeek:id:`Broker::__set_size`: :zeek:type:`function`                           
:zeek:id:`Broker::__table_clear`: :zeek:type:`function`                        
:zeek:id:`Broker::__table_contains`: :zeek:type:`function`                     
:zeek:id:`Broker::__table_create`: :zeek:type:`function`                       
:zeek:id:`Broker::__table_insert`: :zeek:type:`function`                       
:zeek:id:`Broker::__table_iterator`: :zeek:type:`function`                     
:zeek:id:`Broker::__table_iterator_last`: :zeek:type:`function`                
:zeek:id:`Broker::__table_iterator_next`: :zeek:type:`function`                
:zeek:id:`Broker::__table_iterator_value`: :zeek:type:`function`               
:zeek:id:`Broker::__table_lookup`: :zeek:type:`function`                       
:zeek:id:`Broker::__table_remove`: :zeek:type:`function`                       
:zeek:id:`Broker::__table_size`: :zeek:type:`function`                         
:zeek:id:`Broker::__vector_clear`: :zeek:type:`function`                       
:zeek:id:`Broker::__vector_create`: :zeek:type:`function`                      
:zeek:id:`Broker::__vector_insert`: :zeek:type:`function`                      
:zeek:id:`Broker::__vector_iterator`: :zeek:type:`function`                    
:zeek:id:`Broker::__vector_iterator_last`: :zeek:type:`function`               
:zeek:id:`Broker::__vector_iterator_next`: :zeek:type:`function`               
:zeek:id:`Broker::__vector_iterator_value`: :zeek:type:`function`              
:zeek:id:`Broker::__vector_lookup`: :zeek:type:`function`                      
:zeek:id:`Broker::__vector_remove`: :zeek:type:`function`                      
:zeek:id:`Broker::__vector_replace`: :zeek:type:`function`                     
:zeek:id:`Broker::__vector_size`: :zeek:type:`function`                        
============================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Broker::DataType

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::NONE Broker::DataType

      .. zeek:enum:: Broker::BOOL Broker::DataType

      .. zeek:enum:: Broker::INT Broker::DataType

      .. zeek:enum:: Broker::COUNT Broker::DataType

      .. zeek:enum:: Broker::DOUBLE Broker::DataType

      .. zeek:enum:: Broker::STRING Broker::DataType

      .. zeek:enum:: Broker::ADDR Broker::DataType

      .. zeek:enum:: Broker::SUBNET Broker::DataType

      .. zeek:enum:: Broker::PORT Broker::DataType

      .. zeek:enum:: Broker::TIME Broker::DataType

      .. zeek:enum:: Broker::INTERVAL Broker::DataType

      .. zeek:enum:: Broker::ENUM Broker::DataType

      .. zeek:enum:: Broker::SET Broker::DataType

      .. zeek:enum:: Broker::TABLE Broker::DataType

      .. zeek:enum:: Broker::VECTOR Broker::DataType

   Enumerates the possible types that :zeek:see:`Broker::Data` may be in
   terms of Zeek data types.

Functions
#########
.. zeek:id:: Broker::__data

   :Type: :zeek:type:`function` (d: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__data_type

   :Type: :zeek:type:`function` (d: :zeek:type:`Broker::Data`) : :zeek:type:`Broker::DataType`


.. zeek:id:: Broker::__opaque_clone_through_serialization

   :Type: :zeek:type:`function` (d: :zeek:type:`any`) : :zeek:type:`any`


.. zeek:id:: Broker::__record_assign

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__record_create

   :Type: :zeek:type:`function` (sz: :zeek:type:`count`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__record_iterator

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::RecordIterator


.. zeek:id:: Broker::__record_iterator_last

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__record_iterator_next

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__record_iterator_value

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__record_lookup

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__record_size

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`) : :zeek:type:`count`


.. zeek:id:: Broker::__set_clear

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_contains

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_create

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__set_insert

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_iterator

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::SetIterator


.. zeek:id:: Broker::__set_iterator_last

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_iterator_next

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_iterator_value

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__set_remove

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_size

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`count`


.. zeek:id:: Broker::__table_clear

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`bool`


.. zeek:id:: Broker::__table_contains

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__table_create

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__table_insert

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`, val: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__table_iterator

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::TableIterator


.. zeek:id:: Broker::__table_iterator_last

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__table_iterator_next

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__table_iterator_value

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`Broker::TableItem`


.. zeek:id:: Broker::__table_lookup

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__table_remove

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__table_size

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`count`


.. zeek:id:: Broker::__vector_clear

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`bool`


.. zeek:id:: Broker::__vector_create

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_insert

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__vector_iterator

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::VectorIterator


.. zeek:id:: Broker::__vector_iterator_last

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__vector_iterator_next

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__vector_iterator_value

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_lookup

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_remove

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_replace

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_size

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`count`



