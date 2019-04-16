:tocdepth: 3

base/protocols/dns/main.zeek
============================
.. bro:namespace:: DNS

Base DNS analysis script which tracks and logs DNS queries along with
their responses.

:Namespace: DNS
:Imports: :doc:`base/protocols/dns/consts.zeek </scripts/base/protocols/dns/consts.zeek>`, :doc:`base/utils/queue.zeek </scripts/base/utils/queue.zeek>`

Summary
~~~~~~~
Runtime Options
###############
========================================================================== =======================================================================
:bro:id:`DNS::max_pending_msgs`: :bro:type:`count` :bro:attr:`&redef`      Give up trying to match pending DNS queries or replies for a given
                                                                           query/transaction ID once this number of unmatched queries or replies
                                                                           is reached (this shouldn't happen unless either the DNS server/resolver
                                                                           is broken, Bro is not seeing all the DNS traffic, or an AXFR query
                                                                           response is ongoing).
:bro:id:`DNS::max_pending_query_ids`: :bro:type:`count` :bro:attr:`&redef` Give up trying to match pending DNS queries or replies across all
                                                                           query/transaction IDs once there is at least one unmatched query or
                                                                           reply across this number of different query IDs.
========================================================================== =======================================================================

Types
#####
=================================================== ================================================================
:bro:type:`DNS::Info`: :bro:type:`record`           The record type which contains the column fields of the DNS log.
:bro:type:`DNS::PendingMessages`: :bro:type:`table` Yields a queue of :bro:see:`DNS::Info` objects for a given
                                                    DNS message query/transaction ID.
:bro:type:`DNS::State`: :bro:type:`record`          A record type which tracks the status of DNS queries for a given
                                                    :bro:type:`connection`.
=================================================== ================================================================

Redefinitions
#############
================================================================= ==================================
:bro:type:`Log::ID`: :bro:type:`enum`                             The DNS logging stream identifier.
:bro:type:`connection`: :bro:type:`record`                        
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= ==================================

Events
######
========================================= ================================================================
:bro:id:`DNS::log_dns`: :bro:type:`event` An event that can be handled to access the :bro:type:`DNS::Info`
                                          record as it is sent to the logging framework.
========================================= ================================================================

Hooks
#####
============================================ =================================================================
:bro:id:`DNS::do_reply`: :bro:type:`hook`    This is called by the specific dns_*_reply events with a "reply"
                                             which may not represent the full data available from the resource
                                             record, but it's generally considered a summarization of the
                                             responses.
:bro:id:`DNS::set_session`: :bro:type:`hook` A hook that is called whenever a session is being set.
============================================ =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: DNS::max_pending_msgs

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``50``

   Give up trying to match pending DNS queries or replies for a given
   query/transaction ID once this number of unmatched queries or replies
   is reached (this shouldn't happen unless either the DNS server/resolver
   is broken, Bro is not seeing all the DNS traffic, or an AXFR query
   response is ongoing).

.. bro:id:: DNS::max_pending_query_ids

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``50``

   Give up trying to match pending DNS queries or replies across all
   query/transaction IDs once there is at least one unmatched query or
   reply across this number of different query IDs.

Types
#####
.. bro:type:: DNS::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         The earliest time at which a DNS protocol message over the
         associated connection is observed.

      uid: :bro:type:`string` :bro:attr:`&log`
         A unique identifier of the connection over which DNS messages
         are being transferred.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      proto: :bro:type:`transport_proto` :bro:attr:`&log`
         The transport layer protocol of the connection.

      trans_id: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         A 16-bit identifier assigned by the program that generated
         the DNS query.  Also used in responses to match up replies to
         outstanding queries.

      rtt: :bro:type:`interval` :bro:attr:`&log` :bro:attr:`&optional`
         Round trip time for the query and response. This indicates
         the delay between when the request was seen until the
         answer started.

      query: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The domain name that is the subject of the DNS query.

      qclass: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         The QCLASS value specifying the class of the query.

      qclass_name: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         A descriptive name for the class of the query.

      qtype: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         A QTYPE value specifying the type of the query.

      qtype_name: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         A descriptive name for the type of the query.

      rcode: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         The response code value in DNS response messages.

      rcode_name: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         A descriptive name for the response code value.

      AA: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         The Authoritative Answer bit for response messages specifies
         that the responding name server is an authority for the
         domain name in the question section.

      TC: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         The Truncation bit specifies that the message was truncated.

      RD: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         The Recursion Desired bit in a request message indicates that
         the client wants recursive service for this query.

      RA: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         The Recursion Available bit in a response message indicates
         that the name server supports recursive queries.

      Z: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         A reserved field that is usually zero in
         queries and responses.

      answers: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The set of resource descriptions in the query answer.

      TTLs: :bro:type:`vector` of :bro:type:`interval` :bro:attr:`&log` :bro:attr:`&optional`
         The caching intervals of the associated RRs described by the
         *answers* field.

      rejected: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         The DNS query was rejected by the server.

      total_answers: :bro:type:`count` :bro:attr:`&optional`
         The total number of resource records in a reply message's
         answer section.

      total_replies: :bro:type:`count` :bro:attr:`&optional`
         The total number of resource records in a reply message's
         answer, authority, and additional sections.

      saw_query: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Whether the full DNS query has been seen.

      saw_reply: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Whether the full DNS reply has been seen.

      auth: :bro:type:`set` [:bro:type:`string`] :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/dns/auth-addl.zeek` is loaded)

         Authoritative responses for the query.

      addl: :bro:type:`set` [:bro:type:`string`] :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/dns/auth-addl.zeek` is loaded)

         Additional responses for the query.

   The record type which contains the column fields of the DNS log.

.. bro:type:: DNS::PendingMessages

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`Queue::Queue`

   Yields a queue of :bro:see:`DNS::Info` objects for a given
   DNS message query/transaction ID.

.. bro:type:: DNS::State

   :Type: :bro:type:`record`

      pending_query: :bro:type:`DNS::Info` :bro:attr:`&optional`
         A single query that hasn't been matched with a response yet.
         Note this is maintained separate from the *pending_queries*
         field solely for performance reasons -- it's possible that
         *pending_queries* contains further queries for which a response
         has not yet been seen, even for the same transaction ID.

      pending_queries: :bro:type:`DNS::PendingMessages` :bro:attr:`&optional`
         Indexed by query id, returns Info record corresponding to
         queries that haven't been matched with a response yet.

      pending_replies: :bro:type:`DNS::PendingMessages` :bro:attr:`&optional`
         Indexed by query id, returns Info record corresponding to
         replies that haven't been matched with a query yet.

   A record type which tracks the status of DNS queries for a given
   :bro:type:`connection`.

Events
######
.. bro:id:: DNS::log_dns

   :Type: :bro:type:`event` (rec: :bro:type:`DNS::Info`)

   An event that can be handled to access the :bro:type:`DNS::Info`
   record as it is sent to the logging framework.

Hooks
#####
.. bro:id:: DNS::do_reply

   :Type: :bro:type:`hook` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, reply: :bro:type:`string`) : :bro:type:`bool`

   This is called by the specific dns_*_reply events with a "reply"
   which may not represent the full data available from the resource
   record, but it's generally considered a summarization of the
   responses.
   

   :c: The connection record for which to fill in DNS reply data.
   

   :msg: The DNS message header information for the response.
   

   :ans: The general information of a RR response.
   

   :reply: The specific response information according to RR type/class.

.. bro:id:: DNS::set_session

   :Type: :bro:type:`hook` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, is_query: :bro:type:`bool`) : :bro:type:`bool`

   A hook that is called whenever a session is being set.
   This can be used if additional initialization logic needs to happen
   when creating a new session value.
   

   :c: The connection involved in the new session.
   

   :msg: The DNS message header information.
   

   :is_query: Indicator for if this is being called for a query or a response.


