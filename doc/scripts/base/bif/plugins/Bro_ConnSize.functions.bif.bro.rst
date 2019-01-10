:tocdepth: 3

base/bif/plugins/Bro_ConnSize.functions.bif.bro
===============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
================================================================== ===================================================================================
:bro:id:`get_current_conn_bytes_threshold`: :bro:type:`function`   Gets the current byte threshold size for a connection.
:bro:id:`get_current_conn_packets_threshold`: :bro:type:`function` Gets the current packet threshold size for a connection.
:bro:id:`set_current_conn_bytes_threshold`: :bro:type:`function`   Sets the current byte threshold for connection sizes, overwriting any potential old
                                                                   threshold.
:bro:id:`set_current_conn_packets_threshold`: :bro:type:`function` Sets a threshold for connection packets, overwtiting any potential old thresholds.
================================================================== ===================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: get_current_conn_bytes_threshold

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`, is_orig: :bro:type:`bool`) : :bro:type:`count`

   Gets the current byte threshold size for a connection.
   

   :cid: The connection id.
   

   :is_orig: If true, threshold of originator, otherwhise threshold of responder.
   

   :returns: 0 if no threshold is set or the threshold in bytes
   
   .. bro:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                get_current_conn_packets_threshold

.. bro:id:: get_current_conn_packets_threshold

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`, is_orig: :bro:type:`bool`) : :bro:type:`count`

   Gets the current packet threshold size for a connection.
   

   :cid: The connection id.
   

   :is_orig: If true, threshold of originator, otherwhise threshold of responder.
   

   :returns: 0 if no threshold is set or the threshold in packets
   
   .. bro:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                get_current_conn_bytes_threshold

.. bro:id:: set_current_conn_bytes_threshold

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`, threshold: :bro:type:`count`, is_orig: :bro:type:`bool`) : :bro:type:`bool`

   Sets the current byte threshold for connection sizes, overwriting any potential old
   threshold. Be aware that in nearly any case you will want to use the high level API
   instead (ConnThreshold::set_bytes_threshold).
   

   :cid: The connection id.
   

   :threshold: Threshold in bytes.
   

   :is_orig: If true, threshold is set for bytes from originator, otherwhise for bytes from responder.
   
   .. bro:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                get_current_conn_bytes_threshold get_current_conn_packets_threshold

.. bro:id:: set_current_conn_packets_threshold

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`, threshold: :bro:type:`count`, is_orig: :bro:type:`bool`) : :bro:type:`bool`

   Sets a threshold for connection packets, overwtiting any potential old thresholds.
   Be aware that in nearly any case you will want to use the high level API
   instead (ConnThreshold::set_packets_threshold).
   

   :cid: The connection id.
   

   :threshold: Threshold in packets.
   

   :is_orig: If true, threshold is set for packets from originator, otherwhise for packets from responder.
   
   .. bro:see:: set_current_conn_bytes_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                get_current_conn_bytes_threshold get_current_conn_packets_threshold


