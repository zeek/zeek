:tocdepth: 3

base/bif/plugins/Zeek_ConnSize.events.bif.zeek
==============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================== =================================================================
:zeek:id:`conn_bytes_threshold_crossed`: :zeek:type:`event`    Generated for a connection that crossed a set byte threshold.
:zeek:id:`conn_duration_threshold_crossed`: :zeek:type:`event` Generated for a connection that crossed a set duration threshold.
:zeek:id:`conn_packets_threshold_crossed`: :zeek:type:`event`  Generated for a connection that crossed a set packet threshold.
============================================================== =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: conn_bytes_threshold_crossed
   :source-code: base/protocols/conn/thresholds.zeek 320 337

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`)

   Generated for a connection that crossed a set byte threshold. Note that this
   is a low level event that should usually be avoided for user code. Use
   :zeek:see:`ConnThreshold::bytes_threshold_crossed` instead.
   

   :param c: the connection
   

   :param threshold: the threshold that was set
   

   :param is_orig: true if the threshold was crossed by the originator of the connection
   
   .. zeek:see:: set_current_conn_packets_threshold set_current_conn_bytes_threshold conn_packets_threshold_crossed
                 get_current_conn_bytes_threshold get_current_conn_packets_threshold conn_duration_threshold_crossed
                 set_current_conn_duration_threshold get_current_conn_duration_threshold

.. zeek:id:: conn_duration_threshold_crossed
   :source-code: base/protocols/conn/thresholds.zeek 358 370

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, threshold: :zeek:type:`interval`, is_orig: :zeek:type:`bool`)

   Generated for a connection that crossed a set duration threshold. Note that this
   is a low level event that should usually be avoided for user code. Use
   :zeek:see:`ConnThreshold::duration_threshold_crossed` instead.
   
   Note that this event is not raised at the exact moment that a duration threshold is crossed; instead
   it is raised when the next packet is seen after the threshold has been crossed. On a connection that is
   idle, this can be raised significantly later.
   

   :param c: the connection
   

   :param threshold: the threshold that was set
   

   :param is_orig: true if the threshold was crossed by the originator of the connection
   
   .. zeek:see:: set_current_conn_packets_threshold set_current_conn_bytes_threshold conn_bytes_threshold_crossed
                 get_current_conn_bytes_threshold get_current_conn_packets_threshold
                 set_current_conn_duration_threshold get_current_conn_duration_threshold

.. zeek:id:: conn_packets_threshold_crossed
   :source-code: base/protocols/conn/thresholds.zeek 339 356

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`)

   Generated for a connection that crossed a set packet threshold. Note that this
   is a low level event that should usually be avoided for user code. Use
   :zeek:see:`ConnThreshold::packets_threshold_crossed` instead.
   

   :param c: the connection
   

   :param threshold: the threshold that was set
   

   :param is_orig: true if the threshold was crossed by the originator of the connection
   
   .. zeek:see:: set_current_conn_packets_threshold set_current_conn_bytes_threshold conn_bytes_threshold_crossed
                 get_current_conn_bytes_threshold get_current_conn_packets_threshold conn_duration_threshold_crossed
                 set_current_conn_duration_threshold get_current_conn_duration_threshold


