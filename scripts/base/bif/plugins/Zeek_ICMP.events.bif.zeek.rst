:tocdepth: 3

base/bif/plugins/Zeek_ICMP.events.bif.zeek
==========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================== =====================================================================
:zeek:id:`icmp_echo_reply`: :zeek:type:`event`             Generated for ICMP *echo reply* messages.
:zeek:id:`icmp_echo_request`: :zeek:type:`event`           Generated for ICMP *echo request* messages.
:zeek:id:`icmp_error_message`: :zeek:type:`event`          Generated for all ICMPv6 error messages that are not handled
                                                           separately with dedicated events.
:zeek:id:`icmp_neighbor_advertisement`: :zeek:type:`event` Generated for ICMP *neighbor advertisement* messages.
:zeek:id:`icmp_neighbor_solicitation`: :zeek:type:`event`  Generated for ICMP *neighbor solicitation* messages.
:zeek:id:`icmp_packet_too_big`: :zeek:type:`event`         Generated for ICMPv6 *packet too big* messages.
:zeek:id:`icmp_parameter_problem`: :zeek:type:`event`      Generated for ICMPv6 *parameter problem* messages.
:zeek:id:`icmp_redirect`: :zeek:type:`event`               Generated for ICMP *redirect* messages.
:zeek:id:`icmp_router_advertisement`: :zeek:type:`event`   Generated for ICMP *router advertisement* messages.
:zeek:id:`icmp_router_solicitation`: :zeek:type:`event`    Generated for ICMP *router solicitation* messages.
:zeek:id:`icmp_sent`: :zeek:type:`event`                   Generated for all ICMP messages that are not handled separately with
                                                           dedicated ICMP events.
:zeek:id:`icmp_sent_payload`: :zeek:type:`event`           The same as :zeek:see:`icmp_sent` except containing the ICMP payload.
:zeek:id:`icmp_time_exceeded`: :zeek:type:`event`          Generated for ICMP *time exceeded* messages.
:zeek:id:`icmp_unreachable`: :zeek:type:`event`            Generated for ICMP *destination unreachable* messages.
========================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: icmp_echo_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, icmp: :zeek:type:`icmp_conn`, id: :zeek:type:`count`, seq: :zeek:type:`count`, payload: :zeek:type:`string`)

   Generated for ICMP *echo reply* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :id: The *echo reply* identifier.
   

   :seq: The *echo reply* sequence number.
   

   :payload: The message-specific data of the packet payload, i.e., everything
            after the first 8 bytes of the ICMP header.
   
   .. zeek:see:: icmp_echo_request

.. zeek:id:: icmp_echo_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, icmp: :zeek:type:`icmp_conn`, id: :zeek:type:`count`, seq: :zeek:type:`count`, payload: :zeek:type:`string`)

   Generated for ICMP *echo request* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :id: The *echo request* identifier.
   

   :seq: The *echo request* sequence number.
   

   :payload: The message-specific data of the packet payload, i.e., everything
            after the first 8 bytes of the ICMP header.
   
   .. zeek:see:: icmp_echo_reply

.. zeek:id:: icmp_error_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, icmp: :zeek:type:`icmp_conn`, code: :zeek:type:`count`, context: :zeek:type:`icmp_context`)

   Generated for all ICMPv6 error messages that are not handled
   separately with dedicated events. Zeek's ICMP analyzer handles a number
   of ICMP error messages directly with dedicated events. This event acts
   as a fallback for those it doesn't.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/ICMPv6>`__ for more
   information about the ICMPv6 protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :code: The ICMP code of the error message.
   

   :context: A record with specifics of the original packet that the message
            refers to.
   
   .. zeek:see:: icmp_unreachable icmp_packet_too_big
      icmp_time_exceeded icmp_parameter_problem

.. zeek:id:: icmp_neighbor_advertisement

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, icmp: :zeek:type:`icmp_conn`, router: :zeek:type:`bool`, solicited: :zeek:type:`bool`, override: :zeek:type:`bool`, tgt: :zeek:type:`addr`, options: :zeek:type:`icmp6_nd_options`)

   Generated for ICMP *neighbor advertisement* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :router: Flag indicating the sender is a router.
   

   :solicited: Flag indicating advertisement is in response to a solicitation.
   

   :override: Flag indicating advertisement should override existing caches.
   

   :tgt: the Target Address in the soliciting message or the address whose
        link-layer address has changed for unsolicited adverts.
   

   :options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. zeek:see:: icmp_router_solicitation icmp_router_advertisement
      icmp_neighbor_solicitation icmp_redirect

.. zeek:id:: icmp_neighbor_solicitation

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, icmp: :zeek:type:`icmp_conn`, tgt: :zeek:type:`addr`, options: :zeek:type:`icmp6_nd_options`)

   Generated for ICMP *neighbor solicitation* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :tgt: The IP address of the target of the solicitation.
   

   :options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. zeek:see:: icmp_router_solicitation icmp_router_advertisement
      icmp_neighbor_advertisement icmp_redirect

.. zeek:id:: icmp_packet_too_big

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, icmp: :zeek:type:`icmp_conn`, code: :zeek:type:`count`, context: :zeek:type:`icmp_context`)

   Generated for ICMPv6 *packet too big* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/ICMPv6>`__ for more
   information about the ICMPv6 protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :code: The ICMP code of the *too big* message.
   

   :context: A record with specifics of the original packet that the message
            refers to. *Too big* messages should include the original IP header
            from the packet that triggered them, and Zeek parses that into
            the *context* structure. Note that if the *too big* includes only
            a partial IP header for some reason, no fields of *context* will
            be filled out.
   
   .. zeek:see:: icmp_error_message icmp_unreachable
      icmp_time_exceeded icmp_parameter_problem

.. zeek:id:: icmp_parameter_problem

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, icmp: :zeek:type:`icmp_conn`, code: :zeek:type:`count`, context: :zeek:type:`icmp_context`)

   Generated for ICMPv6 *parameter problem* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/ICMPv6>`__ for more
   information about the ICMPv6 protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :code: The ICMP code of the *parameter problem* message.
   

   :context: A record with specifics of the original packet that the message
            refers to. *Parameter problem* messages should include the original
            IP header from the packet that triggered them, and Zeek parses that
            into the *context* structure. Note that if the *parameter problem*
            includes only a partial IP header for some reason, no fields
            of *context* will be filled out.
   
   .. zeek:see:: icmp_error_message icmp_unreachable icmp_packet_too_big
      icmp_time_exceeded

.. zeek:id:: icmp_redirect

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, icmp: :zeek:type:`icmp_conn`, tgt: :zeek:type:`addr`, dest: :zeek:type:`addr`, options: :zeek:type:`icmp6_nd_options`)

   Generated for ICMP *redirect* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :tgt: The address that is supposed to be a better first hop to use for
        ICMP Destination Address.
   

   :dest: The address of the destination which is redirected to the target.
   

   :options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. zeek:see:: icmp_router_solicitation icmp_router_advertisement
      icmp_neighbor_solicitation icmp_neighbor_advertisement

.. zeek:id:: icmp_router_advertisement

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, icmp: :zeek:type:`icmp_conn`, cur_hop_limit: :zeek:type:`count`, managed: :zeek:type:`bool`, other: :zeek:type:`bool`, home_agent: :zeek:type:`bool`, pref: :zeek:type:`count`, proxy: :zeek:type:`bool`, rsv: :zeek:type:`count`, router_lifetime: :zeek:type:`interval`, reachable_time: :zeek:type:`interval`, retrans_timer: :zeek:type:`interval`, options: :zeek:type:`icmp6_nd_options`)

   Generated for ICMP *router advertisement* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :cur_hop_limit: The default value that should be placed in Hop Count field
                  for outgoing IP packets.
   

   :managed: Managed address configuration flag, :rfc:`4861`.
   

   :other: Other stateful configuration flag, :rfc:`4861`.
   

   :home_agent: Mobile IPv6 home agent flag, :rfc:`3775`.
   

   :pref: Router selection preferences, :rfc:`4191`.
   

   :proxy: Neighbor discovery proxy flag, :rfc:`4389`.
   

   :rsv: Remaining two reserved bits of router advertisement flags.
   

   :router_lifetime: How long this router should be used as a default router.
   

   :reachable_time: How long a neighbor should be considered reachable.
   

   :retrans_timer: How long a host should wait before retransmitting.
   

   :options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. zeek:see:: icmp_router_solicitation
      icmp_neighbor_solicitation icmp_neighbor_advertisement icmp_redirect

.. zeek:id:: icmp_router_solicitation

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, icmp: :zeek:type:`icmp_conn`, options: :zeek:type:`icmp6_nd_options`)

   Generated for ICMP *router solicitation* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. zeek:see:: icmp_router_advertisement
      icmp_neighbor_solicitation icmp_neighbor_advertisement icmp_redirect

.. zeek:id:: icmp_sent

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, icmp: :zeek:type:`icmp_conn`)

   Generated for all ICMP messages that are not handled separately with
   dedicated ICMP events. Zeek's ICMP analyzer handles a number of ICMP messages
   directly with dedicated events. This event acts as a fallback for those it
   doesn't.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   
   .. zeek:see:: icmp_error_message icmp_sent_payload

.. zeek:id:: icmp_sent_payload

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, icmp: :zeek:type:`icmp_conn`, payload: :zeek:type:`string`)

   The same as :zeek:see:`icmp_sent` except containing the ICMP payload.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :payload: The payload of the ICMP message.
   
   .. zeek:see:: icmp_error_message icmp_sent_payload

.. zeek:id:: icmp_time_exceeded

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, icmp: :zeek:type:`icmp_conn`, code: :zeek:type:`count`, context: :zeek:type:`icmp_context`)

   Generated for ICMP *time exceeded* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :code: The ICMP code of the *exceeded* message.
   

   :context: A record with specifics of the original packet that the message
            refers to. *Unreachable* messages should include the original IP
            header from the packet that triggered them, and Zeek parses that
            into the *context* structure. Note that if the *exceeded* includes
            only a partial IP header for some reason, no fields of *context*
            will be filled out.
   
   .. zeek:see:: icmp_error_message icmp_unreachable icmp_packet_too_big
      icmp_parameter_problem

.. zeek:id:: icmp_unreachable

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, icmp: :zeek:type:`icmp_conn`, code: :zeek:type:`count`, context: :zeek:type:`icmp_context`)

   Generated for ICMP *destination unreachable* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :code: The ICMP code of the *unreachable* message.
   

   :context: A record with specifics of the original packet that the message
            refers to. *Unreachable* messages should include the original IP
            header from the packet that triggered them, and Zeek parses that
            into the *context* structure. Note that if the *unreachable*
            includes only a partial IP header for some reason, no
            fields of *context* will be filled out.
   
   .. zeek:see:: icmp_error_message icmp_packet_too_big
      icmp_time_exceeded icmp_parameter_problem


