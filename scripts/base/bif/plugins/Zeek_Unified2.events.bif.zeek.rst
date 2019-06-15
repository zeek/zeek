:tocdepth: 3

base/bif/plugins/Zeek_Unified2.events.bif.zeek
==============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================== ========================================================
:zeek:id:`unified2_event`: :zeek:type:`event`  Abstract all of the various Unified2 event formats into 
                                               a single event.
:zeek:id:`unified2_packet`: :zeek:type:`event` The Unified2 packet format event.
============================================== ========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: unified2_event

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, ev: :zeek:type:`Unified2::IDSEvent`)

   Abstract all of the various Unified2 event formats into 
   a single event.
   

   :f: The file.
   

   :ev: TODO.
   

.. zeek:id:: unified2_packet

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, pkt: :zeek:type:`Unified2::Packet`)

   The Unified2 packet format event.
   

   :f: The file.
   

   :pkt: TODO.
   


