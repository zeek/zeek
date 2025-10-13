:tocdepth: 3

base/protocols/dns/main.zeek
============================
.. zeek:namespace:: DNS

Base DNS analysis script which tracks and logs DNS queries along with
their responses.

:Namespace: DNS
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/dns/consts.zeek </scripts/base/protocols/dns/consts.zeek>`, :doc:`base/utils/queue.zeek </scripts/base/utils/queue.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================= =======================================================================
:zeek:id:`DNS::max_pending_msgs`: :zeek:type:`count` :zeek:attr:`&redef`      Give up trying to match pending DNS queries or replies for a given
                                                                              query/transaction ID once this number of unmatched queries or replies
                                                                              is reached (this shouldn't happen unless either the DNS server/resolver
                                                                              is broken, Zeek is not seeing all the DNS traffic, or an AXFR query
                                                                              response is ongoing).
:zeek:id:`DNS::max_pending_query_ids`: :zeek:type:`count` :zeek:attr:`&redef` Give up trying to match pending DNS queries or replies across all
                                                                              query/transaction IDs once there is at least one unmatched query or
                                                                              reply across this number of different query IDs.
============================================================================= =======================================================================

Types
#####
===================================================== ================================================================
:zeek:type:`DNS::Info`: :zeek:type:`record`           The record type which contains the column fields of the DNS log.
:zeek:type:`DNS::PendingMessages`: :zeek:type:`table` Yields a queue of :zeek:see:`DNS::Info` objects for a given
                                                      DNS message query/transaction ID.
:zeek:type:`DNS::State`: :zeek:type:`record`          A record type which tracks the status of DNS queries for a given
                                                      :zeek:type:`connection`.
===================================================== ================================================================

Redefinitions
#############
==================================================================== ===========================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              The DNS logging stream identifier.
                                                                     
                                                                     * :zeek:enum:`DNS::LOG`
:zeek:type:`connection`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`connection`
                                                                     
                                                                       dns: :zeek:type:`DNS::Info` :zeek:attr:`&optional`
                                                                     
                                                                       dns_state: :zeek:type:`DNS::State` :zeek:attr:`&optional`
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== ===========================================================

Events
######
=========================================== =================================================================
:zeek:id:`DNS::log_dns`: :zeek:type:`event` An event that can be handled to access the :zeek:type:`DNS::Info`
                                            record as it is sent to the logging framework.
=========================================== =================================================================

Hooks
#####
============================================================ =================================================================
:zeek:id:`DNS::do_reply`: :zeek:type:`hook`                  This is called by the specific dns_*_reply events with a "reply"
                                                             which may not represent the full data available from the resource
                                                             record, but it's generally considered a summarization of the
                                                             responses.
:zeek:id:`DNS::finalize_dns`: :zeek:type:`Conn::RemovalHook` DNS finalization hook.
:zeek:id:`DNS::log_policy`: :zeek:type:`Log::PolicyHook`     A default logging policy hook for the stream.
:zeek:id:`DNS::set_session`: :zeek:type:`hook`               A hook that is called whenever a session is being set.
============================================================ =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: DNS::max_pending_msgs
   :source-code: base/protocols/dns/main.zeek 126 126

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``50``

   Give up trying to match pending DNS queries or replies for a given
   query/transaction ID once this number of unmatched queries or replies
   is reached (this shouldn't happen unless either the DNS server/resolver
   is broken, Zeek is not seeing all the DNS traffic, or an AXFR query
   response is ongoing).

.. zeek:id:: DNS::max_pending_query_ids
   :source-code: base/protocols/dns/main.zeek 131 131

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``50``

   Give up trying to match pending DNS queries or replies across all
   query/transaction IDs once there is at least one unmatched query or
   reply across this number of different query IDs.

Types
#####
.. zeek:type:: DNS::Info
   :source-code: base/protocols/dns/main.zeek 18 86

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      The earliest time at which a DNS protocol message over the
      associated connection is observed.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      A unique identifier of the connection over which DNS messages
      are being transferred.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: proto :zeek:type:`transport_proto` :zeek:attr:`&log`

      The transport layer protocol of the connection.


   .. zeek:field:: trans_id :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      A 16-bit identifier assigned by the program that generated
      the DNS query.  Also used in responses to match up replies to
      outstanding queries.


   .. zeek:field:: rtt :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&optional`

      Round trip time for the query and response. This indicates
      the delay between when the request was seen until the
      answer started.


   .. zeek:field:: query :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The domain name that is the subject of the DNS query.


   .. zeek:field:: qclass :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      The QCLASS value specifying the class of the query.


   .. zeek:field:: qclass_name :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      A descriptive name for the class of the query.


   .. zeek:field:: qtype :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      A QTYPE value specifying the type of the query.


   .. zeek:field:: qtype_name :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      A descriptive name for the type of the query.


   .. zeek:field:: rcode :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      The response code value in DNS response messages.


   .. zeek:field:: rcode_name :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      A descriptive name for the response code value.


   .. zeek:field:: AA :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      The Authoritative Answer bit for response messages specifies
      that the responding name server is an authority for the
      domain name in the question section.


   .. zeek:field:: TC :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      The Truncation bit specifies that the message was truncated.


   .. zeek:field:: RD :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      The Recursion Desired bit in a request message indicates that
      the client wants recursive service for this query.


   .. zeek:field:: RA :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      The Recursion Available bit in a response message indicates
      that the name server supports recursive queries.


   .. zeek:field:: Z :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      A reserved field that is zero in queries and responses unless
      using DNSSEC. This field represents the 3-bit Z field using
      the specification from RFC 1035.


   .. zeek:field:: answers :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The set of resource descriptions in the query answer.


   .. zeek:field:: TTLs :zeek:type:`vector` of :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&optional`

      The caching intervals of the associated RRs described by the
      *answers* field.


   .. zeek:field:: rejected :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      The DNS query was rejected by the server.


   .. zeek:field:: total_answers :zeek:type:`count` :zeek:attr:`&optional`

      The total number of resource records in a reply message's
      answer section.


   .. zeek:field:: total_replies :zeek:type:`count` :zeek:attr:`&optional`

      The total number of resource records in a reply message's
      answer, authority, and additional sections.


   .. zeek:field:: saw_query :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Whether the full DNS query has been seen.


   .. zeek:field:: saw_reply :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Whether the full DNS reply has been seen.


   .. zeek:field:: auth :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/dns/auth-addl.zeek` is loaded)

      Authoritative responses for the query.


   .. zeek:field:: addl :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/dns/auth-addl.zeek` is loaded)

      Additional responses for the query.


   .. zeek:field:: original_query :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/dns/log-original-query-case.zeek` is loaded)

      Query with original letter casing


   The record type which contains the column fields of the DNS log.

.. zeek:type:: DNS::PendingMessages
   :source-code: base/protocols/dns/main.zeek 119 119

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`Queue::Queue`

   Yields a queue of :zeek:see:`DNS::Info` objects for a given
   DNS message query/transaction ID.

.. zeek:type:: DNS::State
   :source-code: base/protocols/dns/main.zeek 135 150

   :Type: :zeek:type:`record`


   .. zeek:field:: pending_query :zeek:type:`DNS::Info` :zeek:attr:`&optional`

      A single query that hasn't been matched with a response yet.
      Note this is maintained separate from the *pending_queries*
      field solely for performance reasons -- it's possible that
      *pending_queries* contains further queries for which a response
      has not yet been seen, even for the same transaction ID.


   .. zeek:field:: pending_queries :zeek:type:`DNS::PendingMessages` :zeek:attr:`&optional`

      Indexed by query id, returns Info record corresponding to
      queries that haven't been matched with a response yet.


   .. zeek:field:: pending_replies :zeek:type:`DNS::PendingMessages` :zeek:attr:`&optional`

      Indexed by query id, returns Info record corresponding to
      replies that haven't been matched with a query yet.


   A record type which tracks the status of DNS queries for a given
   :zeek:type:`connection`.

Events
######
.. zeek:id:: DNS::log_dns
   :source-code: base/protocols/dns/main.zeek 90 90

   :Type: :zeek:type:`event` (rec: :zeek:type:`DNS::Info`)

   An event that can be handled to access the :zeek:type:`DNS::Info`
   record as it is sent to the logging framework.

Hooks
#####
.. zeek:id:: DNS::do_reply
   :source-code: base/protocols/dns/main.zeek 104 104

   :Type: :zeek:type:`hook` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, reply: :zeek:type:`string`) : :zeek:type:`bool`

   This is called by the specific dns_*_reply events with a "reply"
   which may not represent the full data available from the resource
   record, but it's generally considered a summarization of the
   responses.
   

   :param c: The connection record for which to fill in DNS reply data.
   

   :param msg: The DNS message header information for the response.
   

   :param ans: The general information of a RR response.
   

   :param reply: The specific response information according to RR type/class.

.. zeek:id:: DNS::finalize_dns
   :source-code: base/protocols/dns/main.zeek 643 658

   :Type: :zeek:type:`Conn::RemovalHook`

   DNS finalization hook.  Remaining DNS info may get logged when it's called.

.. zeek:id:: DNS::log_policy
   :source-code: base/protocols/dns/main.zeek 15 15

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.

.. zeek:id:: DNS::set_session
   :source-code: base/protocols/dns/main.zeek 238 346

   :Type: :zeek:type:`hook` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, is_query: :zeek:type:`bool`) : :zeek:type:`bool`

   A hook that is called whenever a session is being set.
   This can be used if additional initialization logic needs to happen
   when creating a new session value.
   

   :param c: The connection involved in the new session.
   

   :param msg: The DNS message header information.
   

   :param is_query: Indicator for if this is being called for a query or a response.


