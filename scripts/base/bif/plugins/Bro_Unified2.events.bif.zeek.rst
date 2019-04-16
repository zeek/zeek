:tocdepth: 3

base/bif/plugins/Bro_Unified2.events.bif.zeek
=============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================ ========================================================
:bro:id:`unified2_event`: :bro:type:`event`  Abstract all of the various Unified2 event formats into 
                                             a single event.
:bro:id:`unified2_packet`: :bro:type:`event` The Unified2 packet format event.
============================================ ========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: unified2_event

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, ev: :bro:type:`Unified2::IDSEvent`)

   Abstract all of the various Unified2 event formats into 
   a single event.
   

   :f: The file.
   

   :ev: TODO.
   

.. bro:id:: unified2_packet

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, pkt: :bro:type:`Unified2::Packet`)

   The Unified2 packet format event.
   

   :f: The file.
   

   :pkt: TODO.
   


