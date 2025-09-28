:tocdepth: 3

base/protocols/conn/main.zeek
=============================
.. zeek:namespace:: Conn

This script manages the tracking/logging of general information regarding
TCP, UDP, and ICMP traffic.  For UDP and ICMP, "connections" are to
be interpreted using flow semantics (sequence of packets from a source
host/port to a destination host/port).  Further, ICMP "ports" are to
be interpreted as the source port meaning the ICMP message type and
the destination port being the ICMP message code.

:Namespace: Conn
:Imports: :doc:`base/utils/site.zeek </scripts/base/utils/site.zeek>`, :doc:`base/utils/strings.zeek </scripts/base/utils/strings.zeek>`

Summary
~~~~~~~
Types
#####
============================================ ===================================================================
:zeek:type:`Conn::Info`: :zeek:type:`record` The record type which contains column fields of the connection log.
============================================ ===================================================================

Redefinitions
#############
============================================ ======================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      The connection logging stream identifier.
                                             
                                             * :zeek:enum:`Conn::LOG`
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               conn: :zeek:type:`Conn::Info` :zeek:attr:`&optional`
============================================ ======================================================

Events
######
============================================= ===============================================================
:zeek:id:`Conn::log_conn`: :zeek:type:`event` Event that can be handled to access the :zeek:type:`Conn::Info`
                                              record as it is sent on to the logging framework.
============================================= ===============================================================

Hooks
#####
========================================================= =============================================
:zeek:id:`Conn::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
========================================================= =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Conn::Info
   :source-code: base/protocols/conn/main.zeek 21 168

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      This is the time of the first packet.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      A unique identifier of the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: proto :zeek:type:`transport_proto` :zeek:attr:`&log`

      The transport layer protocol of the connection.


   .. zeek:field:: service :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      A comma-separated list of confirmed protocol(s).
      With :zeek:see:DPD::track_removed_services_in_connection, the list
      includes the same protocols prefixed with "-" to record that Zeek
      dropped them due to parsing violations."


   .. zeek:field:: duration :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&optional`

      How long the connection lasted.
      
      .. note:: The duration doesn't cover trailing "non-productive"
         TCP packets (i.e., ones not contributing new stream payload)
         once a direction is closed.  For example, for regular
         3-way/4-way connection tear-downs it doesn't include the
         final ACK.  The reason is largely historic: this approach
         allows more accurate computation of connection data rates.
         Zeek does however reflect such trailing packets in the
         connection history.


   .. zeek:field:: orig_bytes :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      The number of payload bytes the originator sent. For TCP
      this is taken from sequence numbers and might be inaccurate
      (e.g., due to large connections).


   .. zeek:field:: resp_bytes :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      The number of payload bytes the responder sent. See
      *orig_bytes*.


   .. zeek:field:: conn_state :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Possible *conn_state* values:
      
      * S0: Connection attempt seen, no reply.
      
      * S1: Connection established, not terminated.
      
      * SF: Normal establishment and termination.
        Note that this is the same symbol as for state S1.
        You can tell the two apart because for S1 there will not be any
        byte counts in the summary, while for SF there will be.
      
      * REJ: Connection attempt rejected.
      
      * S2: Connection established and close attempt by originator seen
        (but no reply from responder).
      
      * S3: Connection established and close attempt by responder seen
        (but no reply from originator).
      
      * RSTO: Connection established, originator aborted (sent a RST).
      
      * RSTR: Responder sent a RST.
      
      * RSTOS0: Originator sent a SYN followed by a RST, we never saw a
        SYN-ACK from the responder.
      
      * RSTRH: Responder sent a SYN ACK followed by a RST, we never saw a
        SYN from the (purported) originator.
      
      * SH: Originator sent a SYN followed by a FIN, we never saw a
        SYN ACK from the responder (hence the connection was "half" open).
      
      * SHR: Responder sent a SYN ACK followed by a FIN, we never saw a
        SYN from the originator.
      
      * OTH: No SYN seen, just midstream traffic (one example of this
        is a "partial connection" that was not later closed).


   .. zeek:field:: local_orig :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      If the connection is originated locally, this value will be T.
      If it was originated remotely it will be F.  In the case that
      the :zeek:id:`Site::local_nets` variable is undefined, this
      field will be left empty at all times.


   .. zeek:field:: local_resp :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      If the connection is responded to locally, this value will be T.
      If it was responded to remotely it will be F.  In the case that
      the :zeek:id:`Site::local_nets` variable is undefined, this
      field will be left empty at all times.


   .. zeek:field:: missed_bytes :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      Indicates the number of bytes missed in content gaps, which
      is representative of packet loss.  A value other than zero
      will normally cause protocol analysis to fail but some
      analysis may have been completed prior to the packet loss.


   .. zeek:field:: history :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Records the state history of connections as a string of
      letters.  The meaning of those letters is:
      
      ======  ====================================================
      Letter  Meaning
      ======  ====================================================
      s       a SYN w/o the ACK bit set
      h       a SYN+ACK ("handshake")
      a       a pure ACK
      d       packet with payload ("data")
      f       packet with FIN bit set
      r       packet with RST bit set
      c       packet with a bad checksum (applies to UDP too)
      g       a content gap
      t       packet with retransmitted payload
      w       packet with a zero window advertisement
      i       inconsistent packet (e.g. FIN+RST bits set)
      q       multi-flag packet (SYN+FIN or SYN+RST bits set)
      ^       connection direction was flipped by Zeek's heuristic
      x       connection analysis partial (e.g. limits exceeded)
      ======  ====================================================
      
      If the event comes from the originator, the letter is in
      upper-case; if it comes from the responder, it's in
      lower-case.  The 'a', 'd', 'i' and 'q' flags are
      recorded a maximum of one time in either direction regardless
      of how many are actually seen.  'f', 'h', 'r' and
      's' can be recorded multiple times for either direction
      if the associated sequence number differs from the
      last-seen packet of the same flag type.
      'c', 'g', 't' and 'w' are recorded in a logarithmic fashion:
      the second instance represents that the event was seen
      (at least) 10 times; the third instance, 100 times; etc.


   .. zeek:field:: orig_pkts :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Number of packets that the originator sent.
      Only set if :zeek:id:`use_conn_size_analyzer` = T.


   .. zeek:field:: orig_ip_bytes :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Number of IP level bytes that the originator sent (as seen on
      the wire, taken from the IP total_length header field).
      Only set if :zeek:id:`use_conn_size_analyzer` = T.


   .. zeek:field:: resp_pkts :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Number of packets that the responder sent.
      Only set if :zeek:id:`use_conn_size_analyzer` = T.


   .. zeek:field:: resp_ip_bytes :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Number of IP level bytes that the responder sent (as seen on
      the wire, taken from the IP total_length header field).
      Only set if :zeek:id:`use_conn_size_analyzer` = T.


   .. zeek:field:: tunnel_parents :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`

      If this connection was over a tunnel, indicate the
      *uid* values for any encapsulating parent connections
      used over the lifetime of this inner connection.


   .. zeek:field:: ip_proto :zeek:type:`count` :zeek:attr:`&optional`

      For IP-based connections, this contains the protocol
      identifier passed in the IP header. This is different
      from the *proto* field in that this value comes
      directly from the header.


   .. zeek:field:: community_id :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      (present if :doc:`/scripts/policy/protocols/conn/community-id-logging.zeek` is loaded)


   .. zeek:field:: failed_service :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional` :zeek:attr:`&ordered`

      (present if :doc:`/scripts/policy/protocols/conn/failed-service-logging.zeek` is loaded)

      List of analyzers in a connection that raised violations
      causing their removal.
      Analyzers are listed in order that they were removed.


   .. zeek:field:: ip_proto_name :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/conn/ip-proto-name-logging.zeek` is loaded)

      A string version of the ip_proto field


   .. zeek:field:: orig_l2_addr :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/conn/mac-logging.zeek` is loaded)

      Link-layer address of the originator, if available.


   .. zeek:field:: resp_l2_addr :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/conn/mac-logging.zeek` is loaded)

      Link-layer address of the responder, if available.


   .. zeek:field:: vlan :zeek:type:`int` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/conn/vlan-logging.zeek` is loaded)

      The outer VLAN for this connection, if applicable.


   .. zeek:field:: inner_vlan :zeek:type:`int` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/conn/vlan-logging.zeek` is loaded)

      The inner VLAN for this connection, if applicable.


   .. zeek:field:: pppoe_session_id :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/conn/pppoe-session-id-logging.zeek` is loaded)

      The PPPoE session id, if applicable for this connection.


   .. zeek:field:: speculative_service :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/conn/speculative-service.zeek` is loaded)

      Protocol that was determined by a matching signature after the beginning
      of a connection. In this situation no analyzer can be attached and hence
      the data cannot be analyzed nor the protocol can be confirmed.


   The record type which contains column fields of the connection log.

Events
######
.. zeek:id:: Conn::log_conn
   :source-code: base/protocols/conn/main.zeek 172 172

   :Type: :zeek:type:`event` (rec: :zeek:type:`Conn::Info`)

   Event that can be handled to access the :zeek:type:`Conn::Info`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: Conn::log_policy
   :source-code: base/protocols/conn/main.zeek 18 18

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


