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
============================================ =
:zeek:type:`connection`: :zeek:type:`record` 
============================================ =

Events
######
======================================================================= ============================================================
:zeek:id:`ConnThreshold::bytes_threshold_crossed`: :zeek:type:`event`   Generated for a connection that crossed a set byte threshold
:zeek:id:`ConnThreshold::packets_threshold_crossed`: :zeek:type:`event` Generated for a connection that crossed a set byte threshold
======================================================================= ============================================================

Functions
#########
========================================================================= ===================================================================================================
:zeek:id:`ConnThreshold::delete_bytes_threshold`: :zeek:type:`function`   Deletes a byte threshold for connection sizes.
:zeek:id:`ConnThreshold::delete_packets_threshold`: :zeek:type:`function` Deletes a packet threshold for connection sizes.
:zeek:id:`ConnThreshold::set_bytes_threshold`: :zeek:type:`function`      Sets a byte threshold for connection sizes, adding it to potentially already existing thresholds.
:zeek:id:`ConnThreshold::set_packets_threshold`: :zeek:type:`function`    Sets a packet threshold for connection sizes, adding it to potentially already existing thresholds.
========================================================================= ===================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: ConnThreshold::Thresholds

   :Type: :zeek:type:`record`

      orig_byte: :zeek:type:`set` [:zeek:type:`count`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         current originator byte thresholds we watch for

      resp_byte: :zeek:type:`set` [:zeek:type:`count`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         current responder byte thresholds we watch for

      orig_packet: :zeek:type:`set` [:zeek:type:`count`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         corrent originator packet thresholds we watch for

      resp_packet: :zeek:type:`set` [:zeek:type:`count`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         corrent responder packet thresholds we watch for


Events
######
.. zeek:id:: ConnThreshold::bytes_threshold_crossed

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`)

   Generated for a connection that crossed a set byte threshold
   

   :c: the connection
   

   :threshold: the threshold that was set
   

   :is_orig: True if the threshold was crossed by the originator of the connection

.. zeek:id:: ConnThreshold::packets_threshold_crossed

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`)

   Generated for a connection that crossed a set byte threshold
   

   :c: the connection
   

   :threshold: the threshold that was set
   

   :is_orig: True if the threshold was crossed by the originator of the connection

Functions
#########
.. zeek:id:: ConnThreshold::delete_bytes_threshold

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`) : :zeek:type:`bool`

   Deletes a byte threshold for connection sizes.
   

   :cid: The connection id.
   

   :threshold: Threshold in bytes to remove.
   

   :is_orig: If true, threshold is removed for packets from originator, otherwhise for packets from responder.
   

   :returns: T on success, F on failure.

.. zeek:id:: ConnThreshold::delete_packets_threshold

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`) : :zeek:type:`bool`

   Deletes a packet threshold for connection sizes.
   

   :cid: The connection id.
   

   :threshold: Threshold in packets.
   

   :is_orig: If true, threshold is removed for packets from originator, otherwise for packets from responder.
   

   :returns: T on success, F on failure.

.. zeek:id:: ConnThreshold::set_bytes_threshold

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`) : :zeek:type:`bool`

   Sets a byte threshold for connection sizes, adding it to potentially already existing thresholds.
   conn_bytes_threshold_crossed will be raised for each set threshold.
   

   :cid: The connection id.
   

   :threshold: Threshold in bytes.
   

   :is_orig: If true, threshold is set for bytes from originator, otherwise for bytes from responder.
   

   :returns: T on success, F on failure.

.. zeek:id:: ConnThreshold::set_packets_threshold

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`) : :zeek:type:`bool`

   Sets a packet threshold for connection sizes, adding it to potentially already existing thresholds.
   conn_packets_threshold_crossed will be raised for each set threshold.
   

   :cid: The connection id.
   

   :threshold: Threshold in packets.
   

   :is_orig: If true, threshold is set for packets from originator, otherwise for packets from responder.
   

   :returns: T on success, F on failure.


