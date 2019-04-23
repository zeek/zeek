:tocdepth: 3

policy/integration/barnyard2/types.zeek
=======================================
.. zeek:namespace:: Barnyard2

This file is separate from the base script so that dependencies can
be loaded in the correct order.

:Namespace: Barnyard2

Summary
~~~~~~~
Types
#####
======================================================================== =
:zeek:type:`Barnyard2::AlertData`: :zeek:type:`record` :zeek:attr:`&log` 
:zeek:type:`Barnyard2::PacketID`: :zeek:type:`record` :zeek:attr:`&log`  
======================================================================== =

Events
######
======================================================== ================================================================
:zeek:id:`Barnyard2::barnyard_alert`: :zeek:type:`event` This is the event that Barnyard2 instances will send if they're 
                                                         configured with the bro_alert output plugin.
======================================================== ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Barnyard2::AlertData

   :Type: :zeek:type:`record`

      sensor_id: :zeek:type:`count` :zeek:attr:`&log`
         Sensor that originated this event.

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp attached to the alert.

      signature_id: :zeek:type:`count` :zeek:attr:`&log`
         Sig id for this generator.

      generator_id: :zeek:type:`count` :zeek:attr:`&log`
         Which generator generated the alert?

      signature_revision: :zeek:type:`count` :zeek:attr:`&log`
         Sig revision for this id.

      classification_id: :zeek:type:`count` :zeek:attr:`&log`
         Event classification.

      classification: :zeek:type:`string` :zeek:attr:`&log`
         Descriptive classification string.

      priority_id: :zeek:type:`count` :zeek:attr:`&log`
         Event priority.

      event_id: :zeek:type:`count` :zeek:attr:`&log`
         Event ID.
   :Attributes: :zeek:attr:`&log`


.. zeek:type:: Barnyard2::PacketID

   :Type: :zeek:type:`record`

      src_ip: :zeek:type:`addr` :zeek:attr:`&log`

      src_p: :zeek:type:`port` :zeek:attr:`&log`

      dst_ip: :zeek:type:`addr` :zeek:attr:`&log`

      dst_p: :zeek:type:`port` :zeek:attr:`&log`
   :Attributes: :zeek:attr:`&log`


Events
######
.. zeek:id:: Barnyard2::barnyard_alert

   :Type: :zeek:type:`event` (id: :zeek:type:`Barnyard2::PacketID`, alert: :zeek:type:`Barnyard2::AlertData`, msg: :zeek:type:`string`, data: :zeek:type:`string`)

   This is the event that Barnyard2 instances will send if they're 
   configured with the bro_alert output plugin.


