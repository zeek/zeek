:tocdepth: 3

base/protocols/conn/thresholds.zeek
===================================
.. zeek:namespace:: ConnThreshold

Implements a generic API to throw events when a connection crosses a
fixed threshold of bytes or packets.

:Namespace: ConnThreshold

Summary
~~~~~~~
Types
#####
=========================================================== =
:zeek:type:`ConnThreshold::Thresholds`: :zeek:type:`record` 
=========================================================== =

Redefinitions
#############
============================================ ===========================================================================
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               thresholds: :zeek:type:`ConnThreshold::Thresholds` :zeek:attr:`&optional`
============================================ ===========================================================================

Events
######
======================================================================== =================================================================
:zeek:id:`ConnThreshold::bytes_threshold_crossed`: :zeek:type:`event`    Generated for a connection that crossed a set byte threshold
:zeek:id:`ConnThreshold::duration_threshold_crossed`: :zeek:type:`event` Generated for a connection that crossed a set duration threshold.
:zeek:id:`ConnThreshold::packets_threshold_crossed`: :zeek:type:`event`  Generated for a connection that crossed a set byte threshold
======================================================================== =================================================================

Functions
#########
========================================================================== ===================================================================================================
:zeek:id:`ConnThreshold::delete_bytes_threshold`: :zeek:type:`function`    Deletes a byte threshold for connection sizes.
:zeek:id:`ConnThreshold::delete_duration_threshold`: :zeek:type:`function` Deletes a duration threshold for a connection.
:zeek:id:`ConnThreshold::delete_packets_threshold`: :zeek:type:`function`  Deletes a packet threshold for connection sizes.
:zeek:id:`ConnThreshold::set_bytes_threshold`: :zeek:type:`function`       Sets a byte threshold for connection sizes, adding it to potentially already existing thresholds.
:zeek:id:`ConnThreshold::set_duration_threshold`: :zeek:type:`function`    Sets a duration threshold for a connection, adding it to potentially already existing thresholds.
:zeek:id:`ConnThreshold::set_packets_threshold`: :zeek:type:`function`     Sets a packet threshold for connection sizes, adding it to potentially already existing thresholds.
========================================================================== ===================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: ConnThreshold::Thresholds
   :source-code: base/protocols/conn/thresholds.zeek 8 14

   :Type: :zeek:type:`record`

      orig_byte: :zeek:type:`set` [:zeek:type:`count`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         current originator byte thresholds we watch for

      resp_byte: :zeek:type:`set` [:zeek:type:`count`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         current responder byte thresholds we watch for

      orig_packet: :zeek:type:`set` [:zeek:type:`count`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         current originator packet thresholds we watch for

      resp_packet: :zeek:type:`set` [:zeek:type:`count`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         current responder packet thresholds we watch for

      duration: :zeek:type:`set` [:zeek:type:`interval`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         current duration thresholds we watch for


Events
######
.. zeek:id:: ConnThreshold::bytes_threshold_crossed
   :source-code: base/protocols/ftp/gridftp.zeek 73 86

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`)

   Generated for a connection that crossed a set byte threshold
   

   :param c: the connection
   

   :param threshold: the threshold that was set
   

   :param is_orig: True if the threshold was crossed by the originator of the connection

.. zeek:id:: ConnThreshold::duration_threshold_crossed
   :source-code: base/protocols/conn/thresholds.zeek 109 109

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, threshold: :zeek:type:`interval`, is_orig: :zeek:type:`bool`)

   Generated for a connection that crossed a set duration threshold. Note that this event is
   not raised at the exact moment that a duration threshold is crossed; instead it is raised
   when the next packet is seen after the threshold has been crossed. On a connection that is
   idle, this can be raised significantly later.
   

   :param c: the connection
   

   :param threshold: the threshold that was set
   

   :param is_orig: True if the threshold was crossed by the originator of the connection

.. zeek:id:: ConnThreshold::packets_threshold_crossed
   :source-code: base/protocols/conn/thresholds.zeek 97 97

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`)

   Generated for a connection that crossed a set byte threshold
   

   :param c: the connection
   

   :param threshold: the threshold that was set
   

   :param is_orig: True if the threshold was crossed by the originator of the connection

Functions
#########
.. zeek:id:: ConnThreshold::delete_bytes_threshold
   :source-code: base/protocols/conn/thresholds.zeek 266 284

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`) : :zeek:type:`bool`

   Deletes a byte threshold for connection sizes.
   

   :param cid: The connection id.
   

   :param threshold: Threshold in bytes to remove.
   

   :param is_orig: If true, threshold is removed for packets from originator, otherwise for packets from responder.
   

   :returns: T on success, F on failure.

.. zeek:id:: ConnThreshold::delete_duration_threshold
   :source-code: base/protocols/conn/thresholds.zeek 306 318

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, threshold: :zeek:type:`interval`) : :zeek:type:`bool`

   Deletes a duration threshold for a connection.
   

   :param cid: The connection id.
   

   :param threshold: Threshold in packets.
   

   :returns: T on success, F on failure.

.. zeek:id:: ConnThreshold::delete_packets_threshold
   :source-code: base/protocols/conn/thresholds.zeek 286 304

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`) : :zeek:type:`bool`

   Deletes a packet threshold for connection sizes.
   

   :param cid: The connection id.
   

   :param threshold: Threshold in packets.
   

   :param is_orig: If true, threshold is removed for packets from originator, otherwise for packets from responder.
   

   :returns: T on success, F on failure.

.. zeek:id:: ConnThreshold::set_bytes_threshold
   :source-code: base/protocols/conn/thresholds.zeek 224 237

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`) : :zeek:type:`bool`

   Sets a byte threshold for connection sizes, adding it to potentially already existing thresholds.
   conn_bytes_threshold_crossed will be raised for each set threshold.
   

   :param cid: The connection id.
   

   :param threshold: Threshold in bytes.
   

   :param is_orig: If true, threshold is set for bytes from originator, otherwise for bytes from responder.
   

   :returns: T on success, F on failure.

.. zeek:id:: ConnThreshold::set_duration_threshold
   :source-code: base/protocols/conn/thresholds.zeek 254 264

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, threshold: :zeek:type:`interval`) : :zeek:type:`bool`

   Sets a duration threshold for a connection, adding it to potentially already existing thresholds.
   conn_duration_threshold_crossed will be raised for each set threshold.
   

   :param cid: The connection id.
   

   :param threshold: Threshold in seconds.
   

   :returns: T on success, F on failure.

.. zeek:id:: ConnThreshold::set_packets_threshold
   :source-code: base/protocols/conn/thresholds.zeek 239 252

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`) : :zeek:type:`bool`

   Sets a packet threshold for connection sizes, adding it to potentially already existing thresholds.
   conn_packets_threshold_crossed will be raised for each set threshold.
   

   :param cid: The connection id.
   

   :param threshold: Threshold in packets.
   

   :param is_orig: If true, threshold is set for packets from originator, otherwise for packets from responder.
   

   :returns: T on success, F on failure.


