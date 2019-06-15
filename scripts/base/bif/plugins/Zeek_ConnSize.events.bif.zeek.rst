:tocdepth: 3

base/bif/plugins/Zeek_ConnSize.events.bif.zeek
==============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================= ===============================================================
:zeek:id:`conn_bytes_threshold_crossed`: :zeek:type:`event`   Generated for a connection that crossed a set byte threshold.
:zeek:id:`conn_packets_threshold_crossed`: :zeek:type:`event` Generated for a connection that crossed a set packet threshold.
============================================================= ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: conn_bytes_threshold_crossed

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`)

   Generated for a connection that crossed a set byte threshold. Note that this
   is a low level event that should usually be avoided for user code. Use
   ConnThreshold::bytes_threshold_crossed instead.
   

   :c: the connection
   

   :threshold: the threshold that was set
   

   :is_orig: true if the threshold was crossed by the originator of the connection
   
   .. zeek:see:: set_current_conn_packets_threshold set_current_conn_bytes_threshold conn_packets_threshold_crossed
                get_current_conn_bytes_threshold get_current_conn_packets_threshold

.. zeek:id:: conn_packets_threshold_crossed

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`)

   Generated for a connection that crossed a set packet threshold. Note that this
   is a low level event that should usually be avoided for user code. Use
   ConnThreshold::bytes_threshold_crossed instead.
   

   :c: the connection
   

   :threshold: the threshold that was set
   

   :is_orig: true if the threshold was crossed by the originator of the connection
   
   .. zeek:see:: set_current_conn_packets_threshold set_current_conn_bytes_threshold conn_bytes_threshold_crossed
                get_current_conn_bytes_threshold get_current_conn_packets_threshold


