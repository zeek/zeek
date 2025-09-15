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
   :source-code: base/bif/plugins/Zeek_ICMP.events.bif.zeek 88 88

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`icmp_info`, id: :zeek:type:`count`, seq: :zeek:type:`count`, payload: :zeek:type:`string`)

   Generated for ICMP *echo reply* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :param c: The connection record for the corresponding ICMP flow.
   

   :param icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param info: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :param id: The *echo reply* identifier.
   

   :param seq: The *echo reply* sequence number.
   

   :param payload: The message-specific data of the packet payload, i.e., everything
            after the first 8 bytes of the ICMP header.
   
   .. zeek:see:: icmp_echo_request

.. zeek:id:: icmp_echo_request
   :source-code: base/bif/plugins/Zeek_ICMP.events.bif.zeek 63 63

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`icmp_info`, id: :zeek:type:`count`, seq: :zeek:type:`count`, payload: :zeek:type:`string`)

   Generated for ICMP *echo request* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :param c: The connection record for the corresponding ICMP flow.
   

   :param icmp: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :param info: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :param id: The *echo request* identifier.
   

   :param seq: The *echo request* sequence number.
   

   :param payload: The message-specific data of the packet payload, i.e., everything
            after the first 8 bytes of the ICMP header.
   
   .. zeek:see:: icmp_echo_reply

.. zeek:id:: icmp_error_message
   :source-code: base/bif/plugins/Zeek_ICMP.events.bif.zeek 115 115

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`icmp_info`, code: :zeek:type:`count`, context: :zeek:type:`icmp_context`)

   Generated for all ICMPv6 error messages that are not handled
   separately with dedicated events. Zeek's ICMP analyzer handles a number
   of ICMP error messages directly with dedicated events. This event acts
   as a fallback for those it doesn't.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/ICMPv6>`__ for more
   information about the ICMPv6 protocol.
   

   :param c: The connection record for the corresponding ICMP flow.
   

   :param icmp: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :param info: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :param code: The ICMP code of the error message.
   

   :param context: A record with specifics of the original packet that the message
            refers to.
   
   .. zeek:see:: icmp_unreachable icmp_packet_too_big
      icmp_time_exceeded icmp_parameter_problem

.. zeek:id:: icmp_neighbor_advertisement
   :source-code: base/bif/plugins/Zeek_ICMP.events.bif.zeek 343 343

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`icmp_info`, router: :zeek:type:`bool`, solicited: :zeek:type:`bool`, override: :zeek:type:`bool`, tgt: :zeek:type:`addr`, options: :zeek:type:`icmp6_nd_options`)

   Generated for ICMP *neighbor advertisement* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :param c: The connection record for the corresponding ICMP flow.
   

   :param icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param info: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param router: Flag indicating the sender is a router.
   

   :param solicited: Flag indicating advertisement is in response to a solicitation.
   

   :param override: Flag indicating advertisement should override existing caches.
   

   :param tgt: the Target Address in the soliciting message or the address whose
        link-layer address has changed for unsolicited adverts.
   

   :param options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. zeek:see:: icmp_router_solicitation icmp_router_advertisement
      icmp_neighbor_solicitation icmp_redirect

.. zeek:id:: icmp_neighbor_solicitation
   :source-code: base/bif/plugins/Zeek_ICMP.events.bif.zeek 313 313

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`icmp_info`, tgt: :zeek:type:`addr`, options: :zeek:type:`icmp6_nd_options`)

   Generated for ICMP *neighbor solicitation* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :param c: The connection record for the corresponding ICMP flow.
   

   :param icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param info: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param tgt: The IP address of the target of the solicitation.
   

   :param options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. zeek:see:: icmp_router_solicitation icmp_router_advertisement
      icmp_neighbor_advertisement icmp_redirect

.. zeek:id:: icmp_packet_too_big
   :source-code: base/bif/plugins/Zeek_ICMP.events.bif.zeek 171 171

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`icmp_info`, code: :zeek:type:`count`, context: :zeek:type:`icmp_context`)

   Generated for ICMPv6 *packet too big* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/ICMPv6>`__ for more
   information about the ICMPv6 protocol.
   

   :param c: The connection record for the corresponding ICMP flow.
   

   :param icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param info: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param code: The ICMP code of the *too big* message.
   

   :param context: A record with specifics of the original packet that the message
            refers to. *Too big* messages should include the original IP header
            from the packet that triggered them, and Zeek parses that into
            the *context* structure. Note that if the *too big* includes only
            a partial IP header for some reason, no fields of *context* will
            be filled out.
   
   .. zeek:see:: icmp_error_message icmp_unreachable
      icmp_time_exceeded icmp_parameter_problem

.. zeek:id:: icmp_parameter_problem
   :source-code: base/bif/plugins/Zeek_ICMP.events.bif.zeek 227 227

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`icmp_info`, code: :zeek:type:`count`, context: :zeek:type:`icmp_context`)

   Generated for ICMPv6 *parameter problem* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/ICMPv6>`__ for more
   information about the ICMPv6 protocol.
   

   :param c: The connection record for the corresponding ICMP flow.
   

   :param icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param info: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param code: The ICMP code of the *parameter problem* message.
   

   :param context: A record with specifics of the original packet that the message
            refers to. *Parameter problem* messages should include the original
            IP header from the packet that triggered them, and Zeek parses that
            into the *context* structure. Note that if the *parameter problem*
            includes only a partial IP header for some reason, no fields
            of *context* will be filled out.
   
   .. zeek:see:: icmp_error_message icmp_unreachable icmp_packet_too_big
      icmp_time_exceeded

.. zeek:id:: icmp_redirect
   :source-code: base/bif/plugins/Zeek_ICMP.events.bif.zeek 369 369

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`icmp_info`, tgt: :zeek:type:`addr`, dest: :zeek:type:`addr`, options: :zeek:type:`icmp6_nd_options`)

   Generated for ICMP *redirect* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :param c: The connection record for the corresponding ICMP flow.
   

   :param icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param info: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param tgt: The address that is supposed to be a better first hop to use for
        ICMP Destination Address.
   

   :param dest: The address of the destination which is redirected to the target.
   

   :param options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. zeek:see:: icmp_router_solicitation icmp_router_advertisement
      icmp_neighbor_solicitation icmp_neighbor_advertisement

.. zeek:id:: icmp_router_advertisement
   :source-code: base/bif/plugins/Zeek_ICMP.events.bif.zeek 290 290

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`icmp_info`, cur_hop_limit: :zeek:type:`count`, managed: :zeek:type:`bool`, other: :zeek:type:`bool`, home_agent: :zeek:type:`bool`, pref: :zeek:type:`count`, proxy: :zeek:type:`bool`, rsv: :zeek:type:`count`, router_lifetime: :zeek:type:`interval`, reachable_time: :zeek:type:`interval`, retrans_timer: :zeek:type:`interval`, options: :zeek:type:`icmp6_nd_options`)

   Generated for ICMP *router advertisement* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :param c: The connection record for the corresponding ICMP flow.
   

   :param icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param info: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param cur_hop_limit: The default value that should be placed in Hop Count field
                  for outgoing IP packets.
   

   :param managed: Managed address configuration flag, :rfc:`4861`.
   

   :param other: Other stateful configuration flag, :rfc:`4861`.
   

   :param home_agent: Mobile IPv6 home agent flag, :rfc:`3775`.
   

   :param pref: Router selection preferences, :rfc:`4191`.
   

   :param proxy: Neighbor discovery proxy flag, :rfc:`4389`.
   

   :param rsv: Remaining two reserved bits of router advertisement flags.
   

   :param router_lifetime: How long this router should be used as a default router.
   

   :param reachable_time: How long a neighbor should be considered reachable.
   

   :param retrans_timer: How long a host should wait before retransmitting.
   

   :param options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. zeek:see:: icmp_router_solicitation
      icmp_neighbor_solicitation icmp_neighbor_advertisement icmp_redirect

.. zeek:id:: icmp_router_solicitation
   :source-code: base/bif/plugins/Zeek_ICMP.events.bif.zeek 248 248

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`icmp_info`, options: :zeek:type:`icmp6_nd_options`)

   Generated for ICMP *router solicitation* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :param c: The connection record for the corresponding ICMP flow.
   

   :param icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param info: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. zeek:see:: icmp_router_advertisement
      icmp_neighbor_solicitation icmp_neighbor_advertisement icmp_redirect

.. zeek:id:: icmp_sent
   :source-code: base/bif/plugins/Zeek_ICMP.events.bif.zeek 22 22

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`icmp_info`)

   Generated for all ICMP messages that are not handled separately with
   dedicated ICMP events. Zeek's ICMP analyzer handles a number of ICMP messages
   directly with dedicated events. This event acts as a fallback for those it
   doesn't.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :param c: The connection record for the corresponding ICMP flow.
   

   :param icmp: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :param info: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   
   .. zeek:see:: icmp_error_message icmp_sent_payload

.. zeek:id:: icmp_sent_payload
   :source-code: base/bif/plugins/Zeek_ICMP.events.bif.zeek 38 38

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`icmp_info`, payload: :zeek:type:`string`)

   The same as :zeek:see:`icmp_sent` except containing the ICMP payload.
   

   :param c: The connection record for the corresponding ICMP flow.
   

   :param icmp: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :param info: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :param payload: The payload of the ICMP message.
   
   .. zeek:see:: icmp_error_message icmp_sent_payload

.. zeek:id:: icmp_time_exceeded
   :source-code: policy/misc/detect-traceroute/main.zeek 100 103

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`icmp_info`, code: :zeek:type:`count`, context: :zeek:type:`icmp_context`)

   Generated for ICMP *time exceeded* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :param c: The connection record for the corresponding ICMP flow.
   

   :param icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param info: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param code: The ICMP code of the *exceeded* message.
   

   :param context: A record with specifics of the original packet that the message
            refers to. *Unreachable* messages should include the original IP
            header from the packet that triggered them, and Zeek parses that
            into the *context* structure. Note that if the *exceeded* includes
            only a partial IP header for some reason, no fields of *context*
            will be filled out.
   
   .. zeek:see:: icmp_error_message icmp_unreachable icmp_packet_too_big
      icmp_parameter_problem

.. zeek:id:: icmp_unreachable
   :source-code: base/bif/plugins/Zeek_ICMP.events.bif.zeek 143 143

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`icmp_info`, code: :zeek:type:`count`, context: :zeek:type:`icmp_context`)

   Generated for ICMP *destination unreachable* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :param c: The connection record for the corresponding ICMP flow.
   

   :param icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param info: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :param code: The ICMP code of the *unreachable* message.
   

   :param context: A record with specifics of the original packet that the message
            refers to. *Unreachable* messages should include the original IP
            header from the packet that triggered them, and Zeek parses that
            into the *context* structure. Note that if the *unreachable*
            includes only a partial IP header for some reason, no
            fields of *context* will be filled out.
   
   .. zeek:see:: icmp_error_message icmp_packet_too_big
      icmp_time_exceeded icmp_parameter_problem


