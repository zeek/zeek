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
=================================================== =====================================================================
:zeek:type:`Broker::BackendType`: :zeek:type:`enum` Enumerates the possible types of broker stores.
:zeek:type:`Broker::DataType`: :zeek:type:`enum`    Enumerates the possible types that :zeek:see:`Broker::Data` may be in
                                                    terms of Zeek data types.
=================================================== =====================================================================

Functions
#########
============================================================================== =
:zeek:id:`Broker::__data`: :zeek:type:`function`
:zeek:id:`Broker::__data_type`: :zeek:type:`function`
:zeek:id:`Broker::__opaque_clone_through_serialization`: :zeek:type:`function`
============================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Broker::BackendType
   :source-code: base/bif/data.bif.zeek 17 17

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::MEMORY Broker::BackendType

      .. zeek:enum:: Broker::SQLITE Broker::BackendType

   Enumerates the possible types of broker stores. This can be removed
   whenever we're happy with it having been enough since &backend was
   disabled.
   Remove in v10.1: Check if this is unused.

.. zeek:type:: Broker::DataType
   :source-code: base/bif/data.bif.zeek 25 25

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
   :source-code: base/bif/data.bif.zeek 48 48

   :Type: :zeek:type:`function` (d: :zeek:type:`any`) : :zeek:type:`Broker::Data`


.. zeek:id:: Broker::__data_type
   :source-code: base/bif/data.bif.zeek 51 51

   :Type: :zeek:type:`function` (d: :zeek:type:`Broker::Data`) : :zeek:type:`Broker::DataType`


.. zeek:id:: Broker::__opaque_clone_through_serialization
   :source-code: base/bif/data.bif.zeek 55 55

   :Type: :zeek:type:`function` (d: :zeek:type:`any`) : :zeek:type:`any`



