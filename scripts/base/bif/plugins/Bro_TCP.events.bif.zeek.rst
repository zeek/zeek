:tocdepth: 3

base/bif/plugins/Bro_TCP.events.bif.zeek
========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================================== =============================================================================
:zeek:id:`connection_EOF`: :zeek:type:`event`               Generated at the end of reassembled TCP connections.
:zeek:id:`connection_SYN_packet`: :zeek:type:`event`        Generated for a SYN packet.
:zeek:id:`connection_attempt`: :zeek:type:`event`           Generated for an unsuccessful connection attempt.
:zeek:id:`connection_established`: :zeek:type:`event`       Generated when seeing a SYN-ACK packet from the responder in a TCP
                                                            handshake.
:zeek:id:`connection_finished`: :zeek:type:`event`          Generated for a TCP connection that finished normally.
:zeek:id:`connection_first_ACK`: :zeek:type:`event`         Generated for the first ACK packet seen for a TCP connection from
                                                            its *originator*.
:zeek:id:`connection_half_finished`: :zeek:type:`event`     Generated when one endpoint of a TCP connection attempted to gracefully close
                                                            the connection, but the other endpoint is in the TCP_INACTIVE state.
:zeek:id:`connection_partial_close`: :zeek:type:`event`     Generated when a previously inactive endpoint attempts to close a TCP
                                                            connection via a normal FIN handshake or an abort RST sequence.
:zeek:id:`connection_pending`: :zeek:type:`event`           Generated for each still-open TCP connection when Bro terminates.
:zeek:id:`connection_rejected`: :zeek:type:`event`          Generated for a rejected TCP connection.
:zeek:id:`connection_reset`: :zeek:type:`event`             Generated when an endpoint aborted a TCP connection.
:zeek:id:`contents_file_write_failure`: :zeek:type:`event`  Generated when failing to write contents of a TCP stream to a file.
:zeek:id:`new_connection_contents`: :zeek:type:`event`      Generated when reassembly starts for a TCP connection.
:zeek:id:`partial_connection`: :zeek:type:`event`           Generated for a new active TCP connection if Bro did not see the initial
                                                            handshake.
:zeek:id:`tcp_contents`: :zeek:type:`event`                 Generated for each chunk of reassembled TCP payload.
:zeek:id:`tcp_multiple_checksum_errors`: :zeek:type:`event` Generated if a TCP flow crosses a checksum-error threshold, per
                                                            'C'/'c' history reporting.
:zeek:id:`tcp_multiple_gap`: :zeek:type:`event`             Generated if a TCP flow crosses a gap threshold, per 'G'/'g' history
                                                            reporting.
:zeek:id:`tcp_multiple_retransmissions`: :zeek:type:`event` Generated if a TCP flow crosses a retransmission threshold, per
                                                            'T'/'t' history reporting.
:zeek:id:`tcp_multiple_zero_windows`: :zeek:type:`event`    Generated if a TCP flow crosses a zero-window threshold, per
                                                            'W'/'w' history reporting.
:zeek:id:`tcp_option`: :zeek:type:`event`                   Generated for each option found in a TCP header.
:zeek:id:`tcp_packet`: :zeek:type:`event`                   Generated for every TCP packet.
:zeek:id:`tcp_rexmit`: :zeek:type:`event`                   TODO.
=========================================================== =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: connection_EOF

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated at the end of reassembled TCP connections. The TCP reassembler
   raised the event once for each endpoint of a connection when it finished
   reassembling the corresponding side of the communication.
   

   :c: The connection.
   

   :is_orig: True if the event is raised for the originator side.
   
   .. zeek:see::  connection_SYN_packet connection_attempt connection_established
      connection_external connection_finished connection_first_ACK
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. zeek:id:: connection_SYN_packet

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, pkt: :zeek:type:`SYN_packet`)

   Generated for a SYN packet. Bro raises this event for every SYN packet seen
   by its TCP analyzer.
   

   :c: The connection.
   

   :pkt: Information extracted from the SYN packet.
   
   .. zeek:see:: connection_EOF  connection_attempt connection_established
      connection_external connection_finished connection_first_ACK
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection
   
   .. note::
   
      This event has quite low-level semantics and can potentially be expensive
      to generate. It should only be used if one really needs the specific
      information passed into the handler via the ``pkt`` argument. If not,
      handling one of the other ``connection_*`` events is typically the
      better approach.

.. zeek:id:: connection_attempt

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for an unsuccessful connection attempt. This event is raised when
   an originator unsuccessfully attempted to establish a connection.
   "Unsuccessful" is defined as at least :zeek:id:`tcp_attempt_delay` seconds
   having elapsed since the originator first sent a connection establishment
   packet to the destination without seeing a reply.
   

   :c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_established
      connection_external connection_finished connection_first_ACK
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. zeek:id:: connection_established

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when seeing a SYN-ACK packet from the responder in a TCP
   handshake.  An associated SYN packet was not seen from the originator
   side if its state is not set to :zeek:see:`TCP_ESTABLISHED`.
   The final ACK of the handshake in response to SYN-ACK may
   or may not occur later, one way to tell is to check the *history* field of
   :zeek:type:`connection` to see if the originator sent an ACK, indicated by
   'A' in the history string.
   

   :c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_external connection_finished connection_first_ACK
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. zeek:id:: connection_finished

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for a TCP connection that finished normally. The event is raised
   when a regular FIN handshake from both endpoints was observed.
   

   :c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_first_ACK
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. zeek:id:: connection_first_ACK

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for the first ACK packet seen for a TCP connection from
   its *originator*.
   

   :c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection
   
   .. note::
   
      This event has quite low-level semantics and should be used only rarely.

.. zeek:id:: connection_half_finished

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when one endpoint of a TCP connection attempted to gracefully close
   the connection, but the other endpoint is in the TCP_INACTIVE state. This can
   happen due to split routing, in which Bro only sees one side of a connection.
   

   :c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_first_ACK  connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. zeek:id:: connection_partial_close

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when a previously inactive endpoint attempts to close a TCP
   connection via a normal FIN handshake or an abort RST sequence. When the
   endpoint sent one of these packets, Bro waits
   :zeek:id:`tcp_partial_close_delay` prior to generating the event, to give
   the other endpoint a chance to close the connection normally.
   

   :c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_first_ACK connection_half_finished connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. zeek:id:: connection_pending

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for each still-open TCP connection when Bro terminates.
   

   :c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection zeek_done

.. zeek:id:: connection_rejected

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for a rejected TCP connection. This event is raised when an
   originator attempted to setup a TCP connection but the responder replied
   with a RST packet denying it.
   

   :c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_pending  connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection
   
   .. note::
   
      If the responder does not respond at all, :zeek:id:`connection_attempt` is
      raised instead. If the responder initially accepts the connection but
      aborts it later, Bro first generates :zeek:id:`connection_established`
      and then :zeek:id:`connection_reset`.

.. zeek:id:: connection_reset

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when an endpoint aborted a TCP connection. The event is raised
   when one endpoint of an established TCP connection aborted by sending a RST
   packet.
   

   :c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_pending connection_rejected  connection_reused
      connection_state_remove connection_status_update connection_timeout
      scheduled_analyzer_applied new_connection new_connection_contents
      partial_connection

.. zeek:id:: contents_file_write_failure

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`string`)

   Generated when failing to write contents of a TCP stream to a file.
   

   :c: The connection whose contents are being recorded.
   

   :is_orig: Which side of the connection encountered a failure to write.
   

   :msg: A reason or description for the failure.
   
   .. zeek:see:: set_contents_file get_contents_file

.. zeek:id:: new_connection_contents

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when reassembly starts for a TCP connection. This event is raised
   at the moment when Bro's TCP analyzer enables stream reassembly for a
   connection.
   

   :c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_pending connection_rejected connection_reset connection_reused
      connection_state_remove connection_status_update connection_timeout
      scheduled_analyzer_applied new_connection partial_connection

.. zeek:id:: partial_connection

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for a new active TCP connection if Bro did not see the initial
   handshake. This event is raised when Bro has observed traffic from each
   endpoint, but the activity did not begin with the usual connection
   establishment.
   

   :c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_pending connection_rejected connection_reset connection_reused
      connection_state_remove connection_status_update connection_timeout
      scheduled_analyzer_applied new_connection new_connection_contents
   

.. zeek:id:: tcp_contents

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, seq: :zeek:type:`count`, contents: :zeek:type:`string`)

   Generated for each chunk of reassembled TCP payload. When content delivery is
   enabled for a TCP connection (via :zeek:id:`tcp_content_delivery_ports_orig`,
   :zeek:id:`tcp_content_delivery_ports_resp`,
   :zeek:id:`tcp_content_deliver_all_orig`,
   :zeek:id:`tcp_content_deliver_all_resp`), this event is raised for each chunk
   of in-order payload reconstructed from the packet stream. Note that this
   event is potentially expensive if many connections carry significant amounts
   of data as then all that data needs to be passed on to the scripting layer.
   

   :c: The connection the payload is part of.
   

   :is_orig: True if the packet was sent by the connection's originator.
   

   :seq: The sequence number corresponding to the first byte of the payload
        chunk.
   

   :contents: The raw payload, which will be non-empty.
   
   .. zeek:see:: tcp_packet tcp_option tcp_rexmit
      tcp_content_delivery_ports_orig tcp_content_delivery_ports_resp
      tcp_content_deliver_all_resp tcp_content_deliver_all_orig
   
   .. note::
   
      The payload received by this event is the same that is also passed into
      application-layer protocol analyzers internally. Subsequent invocations of
      this event for the same connection receive non-overlapping in-order chunks
      of its TCP payload stream. It is however undefined what size each chunk
      has; while Bro passes the data on as soon as possible, specifics depend on
      network-level effects such as latency, acknowledgements, reordering, etc.

.. zeek:id:: tcp_multiple_checksum_errors

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, threshold: :zeek:type:`count`)

   Generated if a TCP flow crosses a checksum-error threshold, per
   'C'/'c' history reporting.
   

   :c: The connection record for the TCP connection.
   

   :is_orig: True if the event is raised for the originator side.
   

   :threshold: the threshold that was crossed
   
   .. zeek:see::  udp_multiple_checksum_errors
      tcp_multiple_zero_windows tcp_multiple_retransmissions tcp_multiple_gap

.. zeek:id:: tcp_multiple_gap

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, threshold: :zeek:type:`count`)

   Generated if a TCP flow crosses a gap threshold, per 'G'/'g' history
   reporting.
   

   :c: The connection record for the TCP connection.
   

   :is_orig: True if the event is raised for the originator side.
   

   :threshold: the threshold that was crossed
   
   .. zeek:see::  tcp_multiple_checksum_errors tcp_multiple_zero_windows tcp_multiple_retransmissions

.. zeek:id:: tcp_multiple_retransmissions

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, threshold: :zeek:type:`count`)

   Generated if a TCP flow crosses a retransmission threshold, per
   'T'/'t' history reporting.
   

   :c: The connection record for the TCP connection.
   

   :is_orig: True if the event is raised for the originator side.
   

   :threshold: the threshold that was crossed
   
   .. zeek:see::  tcp_multiple_checksum_errors tcp_multiple_zero_windows tcp_multiple_gap

.. zeek:id:: tcp_multiple_zero_windows

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, threshold: :zeek:type:`count`)

   Generated if a TCP flow crosses a zero-window threshold, per
   'W'/'w' history reporting.
   

   :c: The connection record for the TCP connection.
   

   :is_orig: True if the event is raised for the originator side.
   

   :threshold: the threshold that was crossed
   
   .. zeek:see::  tcp_multiple_checksum_errors tcp_multiple_retransmissions tcp_multiple_gap

.. zeek:id:: tcp_option

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, opt: :zeek:type:`count`, optlen: :zeek:type:`count`)

   Generated for each option found in a TCP header. Like many of the ``tcp_*``
   events, this is a very low-level event and potentially expensive as it may
   be raised very often.
   

   :c: The connection the packet is part of.
   

   :is_orig: True if the packet was sent by the connection's originator.
   

   :opt: The numerical option number, as found in the TCP header.
   

   :optlen: The length of the options value.
   
   .. zeek:see:: tcp_packet tcp_contents tcp_rexmit
   
   .. note:: There is currently no way to get the actual option value, if any.

.. zeek:id:: tcp_packet

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flags: :zeek:type:`string`, seq: :zeek:type:`count`, ack: :zeek:type:`count`, len: :zeek:type:`count`, payload: :zeek:type:`string`)

   Generated for every TCP packet. This is a very low-level and expensive event
   that should be avoided when at all possible. It's usually infeasible to
   handle when processing even medium volumes of traffic in real-time.  It's
   slightly better than :zeek:id:`new_packet` because it affects only TCP, but
   not much. That said, if you work from a trace and want to do some
   packet-level analysis, it may come in handy.
   

   :c: The connection the packet is part of.
   

   :is_orig: True if the packet was sent by the connection's originator.
   

   :flags: A string with the packet's TCP flags. In the string, each character
          corresponds to one set flag, as follows: ``S`` -> SYN; ``F`` -> FIN;
          ``R`` -> RST; ``A`` -> ACK; ``P`` -> PUSH.
   

   :seq: The packet's relative TCP sequence number.
   

   :ack: If the ACK flag is set for the packet, the packet's relative ACK
        number, else zero.
   

   :len: The length of the TCP payload, as specified in the packet header.
   

   :payload: The raw TCP payload. Note that this may be shorter than *len* if
            the packet was not fully captured.
   
   .. zeek:see:: new_packet packet_contents tcp_option tcp_contents tcp_rexmit

.. zeek:id:: tcp_rexmit

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, seq: :zeek:type:`count`, len: :zeek:type:`count`, data_in_flight: :zeek:type:`count`, window: :zeek:type:`count`)

   TODO.


