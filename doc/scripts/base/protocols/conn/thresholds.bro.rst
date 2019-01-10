:tocdepth: 3

base/protocols/conn/thresholds.bro
==================================
.. bro:namespace:: ConnThreshold

Implements a generic API to throw events when a connection crosses a
fixed threshold of bytes or packets.

:Namespace: ConnThreshold

Summary
~~~~~~~
Types
#####
========================================================= =
:bro:type:`ConnThreshold::Thresholds`: :bro:type:`record` 
========================================================= =

Redefinitions
#############
========================================== =
:bro:type:`connection`: :bro:type:`record` 
========================================== =

Events
######
===================================================================== ============================================================
:bro:id:`ConnThreshold::bytes_threshold_crossed`: :bro:type:`event`   Generated for a connection that crossed a set byte threshold
:bro:id:`ConnThreshold::packets_threshold_crossed`: :bro:type:`event` Generated for a connection that crossed a set byte threshold
===================================================================== ============================================================

Functions
#########
======================================================================= ===================================================================================================
:bro:id:`ConnThreshold::delete_bytes_threshold`: :bro:type:`function`   Deletes a byte threshold for connection sizes.
:bro:id:`ConnThreshold::delete_packets_threshold`: :bro:type:`function` Deletes a packet threshold for connection sizes.
:bro:id:`ConnThreshold::set_bytes_threshold`: :bro:type:`function`      Sets a byte threshold for connection sizes, adding it to potentially already existing thresholds.
:bro:id:`ConnThreshold::set_packets_threshold`: :bro:type:`function`    Sets a packet threshold for connection sizes, adding it to potentially already existing thresholds.
======================================================================= ===================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: ConnThreshold::Thresholds

   :Type: :bro:type:`record`

      orig_byte: :bro:type:`set` [:bro:type:`count`] :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         current originator byte thresholds we watch for

      resp_byte: :bro:type:`set` [:bro:type:`count`] :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         current responder byte thresholds we watch for

      orig_packet: :bro:type:`set` [:bro:type:`count`] :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         corrent originator packet thresholds we watch for

      resp_packet: :bro:type:`set` [:bro:type:`count`] :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         corrent responder packet thresholds we watch for


Events
######
.. bro:id:: ConnThreshold::bytes_threshold_crossed

   :Type: :bro:type:`event` (c: :bro:type:`connection`, threshold: :bro:type:`count`, is_orig: :bro:type:`bool`)

   Generated for a connection that crossed a set byte threshold
   

   :c: the connection
   

   :threshold: the threshold that was set
   

   :is_orig: True if the threshold was crossed by the originator of the connection

.. bro:id:: ConnThreshold::packets_threshold_crossed

   :Type: :bro:type:`event` (c: :bro:type:`connection`, threshold: :bro:type:`count`, is_orig: :bro:type:`bool`)

   Generated for a connection that crossed a set byte threshold
   

   :c: the connection
   

   :threshold: the threshold that was set
   

   :is_orig: True if the threshold was crossed by the originator of the connection

Functions
#########
.. bro:id:: ConnThreshold::delete_bytes_threshold

   :Type: :bro:type:`function` (c: :bro:type:`connection`, threshold: :bro:type:`count`, is_orig: :bro:type:`bool`) : :bro:type:`bool`

   Deletes a byte threshold for connection sizes.
   

   :cid: The connection id.
   

   :threshold: Threshold in bytes to remove.
   

   :is_orig: If true, threshold is removed for packets from originator, otherwhise for packets from responder.
   

   :returns: T on success, F on failure.

.. bro:id:: ConnThreshold::delete_packets_threshold

   :Type: :bro:type:`function` (c: :bro:type:`connection`, threshold: :bro:type:`count`, is_orig: :bro:type:`bool`) : :bro:type:`bool`

   Deletes a packet threshold for connection sizes.
   

   :cid: The connection id.
   

   :threshold: Threshold in packets.
   

   :is_orig: If true, threshold is removed for packets from originator, otherwise for packets from responder.
   

   :returns: T on success, F on failure.

.. bro:id:: ConnThreshold::set_bytes_threshold

   :Type: :bro:type:`function` (c: :bro:type:`connection`, threshold: :bro:type:`count`, is_orig: :bro:type:`bool`) : :bro:type:`bool`

   Sets a byte threshold for connection sizes, adding it to potentially already existing thresholds.
   conn_bytes_threshold_crossed will be raised for each set threshold.
   

   :cid: The connection id.
   

   :threshold: Threshold in bytes.
   

   :is_orig: If true, threshold is set for bytes from originator, otherwise for bytes from responder.
   

   :returns: T on success, F on failure.

.. bro:id:: ConnThreshold::set_packets_threshold

   :Type: :bro:type:`function` (c: :bro:type:`connection`, threshold: :bro:type:`count`, is_orig: :bro:type:`bool`) : :bro:type:`bool`

   Sets a packet threshold for connection sizes, adding it to potentially already existing thresholds.
   conn_packets_threshold_crossed will be raised for each set threshold.
   

   :cid: The connection id.
   

   :threshold: Threshold in packets.
   

   :is_orig: If true, threshold is set for packets from originator, otherwise for packets from responder.
   

   :returns: T on success, F on failure.


