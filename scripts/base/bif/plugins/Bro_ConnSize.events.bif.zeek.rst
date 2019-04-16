:tocdepth: 3

base/bif/plugins/Bro_ConnSize.events.bif.zeek
=============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================================== ===============================================================
:bro:id:`conn_bytes_threshold_crossed`: :bro:type:`event`   Generated for a connection that crossed a set byte threshold.
:bro:id:`conn_packets_threshold_crossed`: :bro:type:`event` Generated for a connection that crossed a set packet threshold.
=========================================================== ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: conn_bytes_threshold_crossed

   :Type: :bro:type:`event` (c: :bro:type:`connection`, threshold: :bro:type:`count`, is_orig: :bro:type:`bool`)

   Generated for a connection that crossed a set byte threshold. Note that this
   is a low level event that should usually be avoided for user code. Use
   ConnThreshold::bytes_threshold_crossed instead.
   

   :c: the connection
   

   :threshold: the threshold that was set
   

   :is_orig: true if the threshold was crossed by the originator of the connection
   
   .. bro:see:: set_current_conn_packets_threshold set_current_conn_bytes_threshold conn_packets_threshold_crossed
                get_current_conn_bytes_threshold get_current_conn_packets_threshold

.. bro:id:: conn_packets_threshold_crossed

   :Type: :bro:type:`event` (c: :bro:type:`connection`, threshold: :bro:type:`count`, is_orig: :bro:type:`bool`)

   Generated for a connection that crossed a set packet threshold. Note that this
   is a low level event that should usually be avoided for user code. Use
   ConnThreshold::bytes_threshold_crossed instead.
   

   :c: the connection
   

   :threshold: the threshold that was set
   

   :is_orig: true if the threshold was crossed by the originator of the connection
   
   .. bro:see:: set_current_conn_packets_threshold set_current_conn_bytes_threshold conn_bytes_threshold_crossed
                get_current_conn_bytes_threshold get_current_conn_packets_threshold


