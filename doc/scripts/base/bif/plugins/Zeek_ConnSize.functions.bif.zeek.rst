:tocdepth: 3

base/bif/plugins/Zeek_ConnSize.functions.bif.zeek
=================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
===================================================================== ===================================================================================
:zeek:id:`get_current_conn_bytes_threshold`: :zeek:type:`function`    
:zeek:id:`get_current_conn_duration_threshold`: :zeek:type:`function` Gets the current duration threshold size for a connection.
:zeek:id:`get_current_conn_packets_threshold`: :zeek:type:`function`  Gets the current packet threshold size for a connection.
:zeek:id:`set_current_conn_bytes_threshold`: :zeek:type:`function`    Sets the current byte threshold for connection sizes, overwriting any potential old
                                                                      threshold.
:zeek:id:`set_current_conn_duration_threshold`: :zeek:type:`function` Sets the current duration threshold for connection, overwriting any potential old
                                                                      threshold.
:zeek:id:`set_current_conn_packets_threshold`: :zeek:type:`function`  Sets a threshold for connection packets, overwriting any potential old thresholds.
===================================================================== ===================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: get_current_conn_bytes_threshold
   :source-code: base/bif/plugins/Zeek_ConnSize.functions.bif.zeek 63 63

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, is_orig: :zeek:type:`bool`) : :zeek:type:`count`

   

   :param cid: The connection id.
   

   :param is_orig: If true, threshold of originator, otherwise threshold of responder.
   

   :returns: 0 if no threshold is set or the threshold in bytes
   
   .. zeek:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                 get_current_conn_packets_threshold set_current_conn_duration_threshold
                 get_current_conn_duration_threshold

.. zeek:id:: get_current_conn_duration_threshold
   :source-code: base/bif/plugins/Zeek_ConnSize.functions.bif.zeek 87 87

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`interval`

   Gets the current duration threshold size for a connection.
   

   :param cid: The connection id.
   

   :returns: 0 if no threshold is set or the threshold in seconds
   
   .. zeek:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                 get_current_conn_packets_threshold set_current_conn_duration_threshold

.. zeek:id:: get_current_conn_packets_threshold
   :source-code: base/bif/plugins/Zeek_ConnSize.functions.bif.zeek 76 76

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, is_orig: :zeek:type:`bool`) : :zeek:type:`count`

   Gets the current packet threshold size for a connection.
   

   :param cid: The connection id.
   

   :param is_orig: If true, threshold of originator, otherwise threshold of responder.
   

   :returns: 0 if no threshold is set or the threshold in packets
   
   .. zeek:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                 get_current_conn_bytes_threshold set_current_conn_duration_threshold get_current_conn_duration_threshold

.. zeek:id:: set_current_conn_bytes_threshold
   :source-code: base/bif/plugins/Zeek_ConnSize.functions.bif.zeek 19 19

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`) : :zeek:type:`bool`

   Sets the current byte threshold for connection sizes, overwriting any potential old
   threshold. Be aware that in nearly any case you will want to use the high level API
   instead (:zeek:see:`ConnThreshold::set_bytes_threshold`).
   

   :param cid: The connection id.
   

   :param threshold: Threshold in bytes.
   

   :param is_orig: If true, threshold is set for bytes from originator, otherwise for bytes from responder.
   
   .. zeek:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                 get_current_conn_bytes_threshold get_current_conn_packets_threshold
                 set_current_conn_duration_threshold get_current_conn_duration_threshold

.. zeek:id:: set_current_conn_duration_threshold
   :source-code: base/bif/plugins/Zeek_ConnSize.functions.bif.zeek 49 49

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, threshold: :zeek:type:`interval`) : :zeek:type:`bool`

   Sets the current duration threshold for connection, overwriting any potential old
   threshold. Be aware that in nearly any case you will want to use the high level API
   instead (:zeek:see:`ConnThreshold::set_duration_threshold`).
   

   :param cid: The connection id.
   

   :param threshold: Threshold in seconds.
   
   .. zeek:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                 get_current_conn_bytes_threshold get_current_conn_packets_threshold
                 get_current_conn_duration_threshold

.. zeek:id:: set_current_conn_packets_threshold
   :source-code: base/bif/plugins/Zeek_ConnSize.functions.bif.zeek 35 35

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`) : :zeek:type:`bool`

   Sets a threshold for connection packets, overwriting any potential old thresholds.
   Be aware that in nearly any case you will want to use the high level API
   instead (:zeek:see:`ConnThreshold::set_packets_threshold`).
   

   :param cid: The connection id.
   

   :param threshold: Threshold in packets.
   

   :param is_orig: If true, threshold is set for packets from originator, otherwise for packets from responder.
   
   .. zeek:see:: set_current_conn_bytes_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                 get_current_conn_bytes_threshold get_current_conn_packets_threshold
                 set_current_conn_duration_threshold get_current_conn_duration_threshold


