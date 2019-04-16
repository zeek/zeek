:tocdepth: 3

policy/integration/barnyard2/types.zeek
=======================================
.. bro:namespace:: Barnyard2

This file is separate from the base script so that dependencies can
be loaded in the correct order.

:Namespace: Barnyard2

Summary
~~~~~~~
Types
#####
===================================================================== =
:bro:type:`Barnyard2::AlertData`: :bro:type:`record` :bro:attr:`&log` 
:bro:type:`Barnyard2::PacketID`: :bro:type:`record` :bro:attr:`&log`  
===================================================================== =

Events
######
====================================================== ================================================================
:bro:id:`Barnyard2::barnyard_alert`: :bro:type:`event` This is the event that Barnyard2 instances will send if they're 
                                                       configured with the bro_alert output plugin.
====================================================== ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: Barnyard2::AlertData

   :Type: :bro:type:`record`

      sensor_id: :bro:type:`count` :bro:attr:`&log`
         Sensor that originated this event.

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp attached to the alert.

      signature_id: :bro:type:`count` :bro:attr:`&log`
         Sig id for this generator.

      generator_id: :bro:type:`count` :bro:attr:`&log`
         Which generator generated the alert?

      signature_revision: :bro:type:`count` :bro:attr:`&log`
         Sig revision for this id.

      classification_id: :bro:type:`count` :bro:attr:`&log`
         Event classification.

      classification: :bro:type:`string` :bro:attr:`&log`
         Descriptive classification string.

      priority_id: :bro:type:`count` :bro:attr:`&log`
         Event priority.

      event_id: :bro:type:`count` :bro:attr:`&log`
         Event ID.
   :Attributes: :bro:attr:`&log`


.. bro:type:: Barnyard2::PacketID

   :Type: :bro:type:`record`

      src_ip: :bro:type:`addr` :bro:attr:`&log`

      src_p: :bro:type:`port` :bro:attr:`&log`

      dst_ip: :bro:type:`addr` :bro:attr:`&log`

      dst_p: :bro:type:`port` :bro:attr:`&log`
   :Attributes: :bro:attr:`&log`


Events
######
.. bro:id:: Barnyard2::barnyard_alert

   :Type: :bro:type:`event` (id: :bro:type:`Barnyard2::PacketID`, alert: :bro:type:`Barnyard2::AlertData`, msg: :bro:type:`string`, data: :bro:type:`string`)

   This is the event that Barnyard2 instances will send if they're 
   configured with the bro_alert output plugin.


