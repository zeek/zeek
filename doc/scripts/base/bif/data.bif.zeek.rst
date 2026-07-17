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
   :source-code: base/bif/data.bif.zeek 15 15

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
   :source-code: base/bif/data.bif.zeek 38 38

   :Type: :zeek:type:`function` (d: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__data_type
   :source-code: base/bif/data.bif.zeek 41 41

   :Type: :zeek:type:`function` (d: :zeek:type:`Broker::Data`) : :zeek:type:`Broker::DataType`


.. zeek:id:: Broker::__opaque_clone_through_serialization
   :source-code: base/bif/data.bif.zeek 45 45

   :Type: :zeek:type:`function` (d: :zeek:type:`any`) : :zeek:type:`any`


.. zeek:id:: Broker::__record_assign
   :source-code: base/bif/data.bif.zeek 150 150

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__record_create
   :source-code: base/bif/data.bif.zeek 144 144

   :Type: :zeek:type:`function` (sz: :zeek:type:`count`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__record_iterator
   :source-code: base/bif/data.bif.zeek 156 156

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::RecordIterator


.. zeek:id:: Broker::__record_iterator_last
   :source-code: base/bif/data.bif.zeek 159 159

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__record_iterator_next
   :source-code: base/bif/data.bif.zeek 162 162

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__record_iterator_value
   :source-code: base/bif/data.bif.zeek 165 165

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__record_lookup
   :source-code: base/bif/data.bif.zeek 153 153

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__record_size
   :source-code: base/bif/data.bif.zeek 147 147

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`) : :zeek:type:`count`


.. zeek:id:: Broker::__set_clear
   :source-code: base/bif/data.bif.zeek 51 51

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_contains
   :source-code: base/bif/data.bif.zeek 57 57

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_create
   :source-code: base/bif/data.bif.zeek 48 48

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__set_insert
   :source-code: base/bif/data.bif.zeek 60 60

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_iterator
   :source-code: base/bif/data.bif.zeek 66 66

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::SetIterator


.. zeek:id:: Broker::__set_iterator_last
   :source-code: base/bif/data.bif.zeek 69 69

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_iterator_next
   :source-code: base/bif/data.bif.zeek 72 72

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_iterator_value
   :source-code: base/bif/data.bif.zeek 75 75

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__set_remove
   :source-code: base/bif/data.bif.zeek 63 63

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_size
   :source-code: base/bif/data.bif.zeek 54 54

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`count`


.. zeek:id:: Broker::__table_clear
   :source-code: base/bif/data.bif.zeek 81 81

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`bool`


.. zeek:id:: Broker::__table_contains
   :source-code: base/bif/data.bif.zeek 87 87

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__table_create
   :source-code: base/bif/data.bif.zeek 78 78

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__table_insert
   :source-code: base/bif/data.bif.zeek 90 90

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`, val: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__table_iterator
   :source-code: base/bif/data.bif.zeek 99 99

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::TableIterator


.. zeek:id:: Broker::__table_iterator_last
   :source-code: base/bif/data.bif.zeek 102 102

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__table_iterator_next
   :source-code: base/bif/data.bif.zeek 105 105

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__table_iterator_value
   :source-code: base/bif/data.bif.zeek 108 108

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`Broker::TableItem`


.. zeek:id:: Broker::__table_lookup
   :source-code: base/bif/data.bif.zeek 96 96

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__table_remove
   :source-code: base/bif/data.bif.zeek 93 93

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__table_size
   :source-code: base/bif/data.bif.zeek 84 84

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`count`


.. zeek:id:: Broker::__vector_clear
   :source-code: base/bif/data.bif.zeek 114 114

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`bool`


.. zeek:id:: Broker::__vector_create
   :source-code: base/bif/data.bif.zeek 111 111

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_insert
   :source-code: base/bif/data.bif.zeek 120 120

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Broker::__vector_iterator
   :source-code: base/bif/data.bif.zeek 132 132

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::VectorIterator


.. zeek:id:: Broker::__vector_iterator_last
   :source-code: base/bif/data.bif.zeek 135 135

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__vector_iterator_next
   :source-code: base/bif/data.bif.zeek 138 138

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`bool`


.. zeek:id:: Broker::__vector_iterator_value
   :source-code: base/bif/data.bif.zeek 141 141

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_lookup
   :source-code: base/bif/data.bif.zeek 129 129

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_remove
   :source-code: base/bif/data.bif.zeek 126 126

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_replace
   :source-code: base/bif/data.bif.zeek 123 123

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__vector_size
   :source-code: base/bif/data.bif.zeek 117 117

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`count`



