:tocdepth: 3

base/frameworks/broker/data.zeek
================================
.. zeek:namespace:: Broker

The Broker-based Data API and its various options.

:Namespace: Broker
:Imports: :doc:`base/bif/data.bif.zeek </scripts/base/bif/data.bif.zeek>`, :doc:`base/frameworks/broker/main.zeek </scripts/base/frameworks/broker/main.zeek>`

Summary
~~~~~~~
Functions
#########
==================================================================================== =============================================================
:zeek:id:`Broker::data`: :zeek:type:`function` :zeek:attr:`&deprecated` = *...*      Convert any Zeek value to communication data.
:zeek:id:`Broker::data_type`: :zeek:type:`function` :zeek:attr:`&deprecated` = *...* Retrieve the type of data associated with communication data.
==================================================================================== =============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Broker::data
   :source-code: base/frameworks/broker/data.zeek 38 41

   :Type: :zeek:type:`function` (d: :zeek:type:`any`) : :zeek:type:`Broker::Data`
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in v10.1. This API is not useful after removal of Broker stores."*

   Convert any Zeek value to communication data.

   .. note:: Normally you won't need to use this function as data
      conversion happens implicitly when passing Zeek values into Broker
      functions.


   :param d: any Zeek value to attempt to convert (not all types are supported).


   :returns: the converted communication data.  If the supplied Zeek data
            type does not support conversion to communication data, the
            returned record's optional field will not be set.

.. zeek:id:: Broker::data_type
   :source-code: base/frameworks/broker/data.zeek 33 36

   :Type: :zeek:type:`function` (d: :zeek:type:`Broker::Data`) : :zeek:type:`Broker::DataType`
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in v10.1. This API is not useful after removal of Broker stores."*

   Retrieve the type of data associated with communication data.


   :param d: the communication data.


   :returns: The data type associated with the communication data.
            Note that Broker represents records in the same way as
            vectors, so there is no "record" type.


