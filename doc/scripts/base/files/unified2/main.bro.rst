:tocdepth: 3

base/files/unified2/main.bro
============================
.. bro:namespace:: Unified2


:Namespace: Unified2
:Imports: :doc:`base/utils/dir.bro </scripts/base/utils/dir.bro>`, :doc:`base/utils/paths.bro </scripts/base/utils/paths.bro>`

Summary
~~~~~~~
Redefinable Options
###################
================================================================================ =====================================================================
:bro:id:`Unified2::classification_config`: :bro:type:`string` :bro:attr:`&redef` The classification.config file you would like to use for your alerts.
:bro:id:`Unified2::gen_msg`: :bro:type:`string` :bro:attr:`&redef`               The gen-msg.map file you would like to use for your alerts.
:bro:id:`Unified2::sid_msg`: :bro:type:`string` :bro:attr:`&redef`               The sid-msg.map file you would like to use for your alerts.
:bro:id:`Unified2::watch_dir`: :bro:type:`string` :bro:attr:`&redef`             Directory to watch for Unified2 records.
:bro:id:`Unified2::watch_file`: :bro:type:`string` :bro:attr:`&redef`            File to watch for Unified2 files.
================================================================================ =====================================================================

Types
#####
=================================================================== =
:bro:type:`Unified2::Info`: :bro:type:`record` :bro:attr:`&log`     
:bro:type:`Unified2::PacketID`: :bro:type:`record` :bro:attr:`&log` 
=================================================================== =

Redefinitions
#############
========================================================== =
:bro:type:`Log::ID`: :bro:type:`enum`                      
:bro:type:`fa_file`: :bro:type:`record` :bro:attr:`&redef` 
========================================================== =

Events
######
=================================================== ===================================================
:bro:id:`Unified2::alert`: :bro:type:`event`        Reconstructed "alert" which combines related events
                                                    and packets.
:bro:id:`Unified2::log_unified2`: :bro:type:`event` The event for accessing logged records.
=================================================== ===================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Unified2::classification_config

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   The classification.config file you would like to use for your alerts.

.. bro:id:: Unified2::gen_msg

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   The gen-msg.map file you would like to use for your alerts.

.. bro:id:: Unified2::sid_msg

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   The sid-msg.map file you would like to use for your alerts.

.. bro:id:: Unified2::watch_dir

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Directory to watch for Unified2 records.

.. bro:id:: Unified2::watch_file

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   File to watch for Unified2 files.

Types
#####
.. bro:type:: Unified2::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp attached to the alert.

      id: :bro:type:`Unified2::PacketID` :bro:attr:`&log`
         Addresses and ports for the connection.

      sensor_id: :bro:type:`count` :bro:attr:`&log`
         Sensor that originated this event.

      signature_id: :bro:type:`count` :bro:attr:`&log`
         Sig id for this generator.

      signature: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         A string representation of the *signature_id* field if a sid_msg.map file was loaded.

      generator_id: :bro:type:`count` :bro:attr:`&log`
         Which generator generated the alert?

      generator: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         A string representation of the *generator_id* field if a gen_msg.map file was loaded.

      signature_revision: :bro:type:`count` :bro:attr:`&log`
         Sig revision for this id.

      classification_id: :bro:type:`count` :bro:attr:`&log`
         Event classification.

      classification: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         Descriptive classification string.

      priority_id: :bro:type:`count` :bro:attr:`&log`
         Event priority.

      event_id: :bro:type:`count` :bro:attr:`&log`
         Event ID.

      packet: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         Some of the packet data.
   :Attributes: :bro:attr:`&log`


.. bro:type:: Unified2::PacketID

   :Type: :bro:type:`record`

      src_ip: :bro:type:`addr` :bro:attr:`&log`

      src_p: :bro:type:`port` :bro:attr:`&log`

      dst_ip: :bro:type:`addr` :bro:attr:`&log`

      dst_p: :bro:type:`port` :bro:attr:`&log`
   :Attributes: :bro:attr:`&log`


Events
######
.. bro:id:: Unified2::alert

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, ev: :bro:type:`Unified2::IDSEvent`, pkt: :bro:type:`Unified2::Packet`)

   Reconstructed "alert" which combines related events
   and packets.

.. bro:id:: Unified2::log_unified2

   :Type: :bro:type:`event` (rec: :bro:type:`Unified2::Info`)

   The event for accessing logged records.


