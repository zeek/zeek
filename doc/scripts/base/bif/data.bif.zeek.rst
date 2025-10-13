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
   :source-code: base/bif/data.bif.zeek 14 14

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
   :source-code: base/bif/data.bif.zeek 37 37

   :Type: :zeek:type:`function` (d: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__data_type
   :source-code: base/bif/data.bif.zeek 40 40

   :Type: :zeek:type:`function` (d: :zeek:type:`Broker::Data`) : :zeek:type:`Broker::DataType`


.. zeek:id:: Broker::__opaque_clone_through_serialization
   :source-code: base/bif/data.bif.zeek 44 44

   :Type: :zeek:type:`function` (d: :zeek:type:`any`) : :zeek:type:`any`


.. zeek:id:: Broker::__record_assign
   :source-code: base/bif/data.bif.zeek 149 149

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__record_create
   :source-code: base/bif/data.bif.zeek 143 143

   :Type: :zeek:type:`function` (sz: :zeek:type:`count`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__record_iterator
   :source-code: base/bif/data.bif.zeek 155 155

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::RecordIterator


.. zeek:id:: Broker::__record_iterator_last
   :source-code: base/bif/data.bif.zeek 158 158

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__record_iterator_next
   :source-code: base/bif/data.bif.zeek 161 161

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__record_iterator_value
   :source-code: base/bif/data.bif.zeek 164 164

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__record_lookup
   :source-code: base/bif/data.bif.zeek 152 152

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__record_size
   :source-code: base/bif/data.bif.zeek 146 146

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`) : :zeek:type:`count`


.. zeek:id:: Broker::__set_clear
   :source-code: base/bif/data.bif.zeek 50 50

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_contains
   :source-code: base/bif/data.bif.zeek 56 56

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_create
   :source-code: base/bif/data.bif.zeek 47 47

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__set_insert
   :source-code: base/bif/data.bif.zeek 59 59

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_iterator
   :source-code: base/bif/data.bif.zeek 65 65

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::SetIterator


.. zeek:id:: Broker::__set_iterator_last
   :source-code: base/bif/data.bif.zeek 68 68

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_iterator_next
   :source-code: base/bif/data.bif.zeek 71 71

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_iterator_value
   :source-code: base/bif/data.bif.zeek 74 74

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__set_remove
   :source-code: base/bif/data.bif.zeek 62 62

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_size
   :source-code: base/bif/data.bif.zeek 53 53

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`count`


.. zeek:id:: Broker::__table_clear
   :source-code: base/bif/data.bif.zeek 80 80

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`bool`


.. zeek:id:: Broker::__table_contains
   :source-code: base/bif/data.bif.zeek 86 86

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__table_create
   :source-code: base/bif/data.bif.zeek 77 77

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__table_insert
   :source-code: base/bif/data.bif.zeek 89 89

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`, val: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__table_iterator
   :source-code: base/bif/data.bif.zeek 98 98

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::TableIterator


.. zeek:id:: Broker::__table_iterator_last
   :source-code: base/bif/data.bif.zeek 101 101

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__table_iterator_next
   :source-code: base/bif/data.bif.zeek 104 104

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__table_iterator_value
   :source-code: base/bif/data.bif.zeek 107 107

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`Broker::TableItem`


.. zeek:id:: Broker::__table_lookup
   :source-code: base/bif/data.bif.zeek 95 95

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__table_remove
   :source-code: base/bif/data.bif.zeek 92 92

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__table_size
   :source-code: base/bif/data.bif.zeek 83 83

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`count`


.. zeek:id:: Broker::__vector_clear
   :source-code: base/bif/data.bif.zeek 113 113

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`bool`


.. zeek:id:: Broker::__vector_create
   :source-code: base/bif/data.bif.zeek 110 110

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_insert
   :source-code: base/bif/data.bif.zeek 119 119

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__vector_iterator
   :source-code: base/bif/data.bif.zeek 131 131

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::VectorIterator


.. zeek:id:: Broker::__vector_iterator_last
   :source-code: base/bif/data.bif.zeek 134 134

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__vector_iterator_next
   :source-code: base/bif/data.bif.zeek 137 137

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__vector_iterator_value
   :source-code: base/bif/data.bif.zeek 140 140

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_lookup
   :source-code: base/bif/data.bif.zeek 128 128

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_remove
   :source-code: base/bif/data.bif.zeek 125 125

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_replace
   :source-code: base/bif/data.bif.zeek 122 122

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_size
   :source-code: base/bif/data.bif.zeek 116 116

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`count`



