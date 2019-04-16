:tocdepth: 3

base/bif/plugins/Bro_ICMP.events.bif.zeek
=========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================== ====================================================================
:bro:id:`icmp_echo_reply`: :bro:type:`event`             Generated for ICMP *echo reply* messages.
:bro:id:`icmp_echo_request`: :bro:type:`event`           Generated for ICMP *echo request* messages.
:bro:id:`icmp_error_message`: :bro:type:`event`          Generated for all ICMPv6 error messages that are not handled
                                                         separately with dedicated events.
:bro:id:`icmp_neighbor_advertisement`: :bro:type:`event` Generated for ICMP *neighbor advertisement* messages.
:bro:id:`icmp_neighbor_solicitation`: :bro:type:`event`  Generated for ICMP *neighbor solicitation* messages.
:bro:id:`icmp_packet_too_big`: :bro:type:`event`         Generated for ICMPv6 *packet too big* messages.
:bro:id:`icmp_parameter_problem`: :bro:type:`event`      Generated for ICMPv6 *parameter problem* messages.
:bro:id:`icmp_redirect`: :bro:type:`event`               Generated for ICMP *redirect* messages.
:bro:id:`icmp_router_advertisement`: :bro:type:`event`   Generated for ICMP *router advertisement* messages.
:bro:id:`icmp_router_solicitation`: :bro:type:`event`    Generated for ICMP *router solicitation* messages.
:bro:id:`icmp_sent`: :bro:type:`event`                   Generated for all ICMP messages that are not handled separately with
                                                         dedicated ICMP events.
:bro:id:`icmp_sent_payload`: :bro:type:`event`           The same as :bro:see:`icmp_sent` except containing the ICMP payload.
:bro:id:`icmp_time_exceeded`: :bro:type:`event`          Generated for ICMP *time exceeded* messages.
:bro:id:`icmp_unreachable`: :bro:type:`event`            Generated for ICMP *destination unreachable* messages.
======================================================== ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: icmp_echo_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, id: :bro:type:`count`, seq: :bro:type:`count`, payload: :bro:type:`string`)

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
   
   .. bro:see:: icmp_echo_request

.. bro:id:: icmp_echo_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, id: :bro:type:`count`, seq: :bro:type:`count`, payload: :bro:type:`string`)

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
   
   .. bro:see:: icmp_echo_reply

.. bro:id:: icmp_error_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, code: :bro:type:`count`, context: :bro:type:`icmp_context`)

   Generated for all ICMPv6 error messages that are not handled
   separately with dedicated events. Bro's ICMP analyzer handles a number
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
   
   .. bro:see:: icmp_unreachable icmp_packet_too_big
      icmp_time_exceeded icmp_parameter_problem

.. bro:id:: icmp_neighbor_advertisement

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, router: :bro:type:`bool`, solicited: :bro:type:`bool`, override: :bro:type:`bool`, tgt: :bro:type:`addr`, options: :bro:type:`icmp6_nd_options`)

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
   
   .. bro:see:: icmp_router_solicitation icmp_router_advertisement
      icmp_neighbor_solicitation icmp_redirect

.. bro:id:: icmp_neighbor_solicitation

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, tgt: :bro:type:`addr`, options: :bro:type:`icmp6_nd_options`)

   Generated for ICMP *neighbor solicitation* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :tgt: The IP address of the target of the solicitation.
   

   :options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. bro:see:: icmp_router_solicitation icmp_router_advertisement
      icmp_neighbor_advertisement icmp_redirect

.. bro:id:: icmp_packet_too_big

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, code: :bro:type:`count`, context: :bro:type:`icmp_context`)

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
            from the packet that triggered them, and Bro parses that into
            the *context* structure. Note that if the *too big* includes only
            a partial IP header for some reason, no fields of *context* will
            be filled out.
   
   .. bro:see:: icmp_error_message icmp_unreachable
      icmp_time_exceeded icmp_parameter_problem

.. bro:id:: icmp_parameter_problem

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, code: :bro:type:`count`, context: :bro:type:`icmp_context`)

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
            IP header from the packet that triggered them, and Bro parses that
            into the *context* structure. Note that if the *parameter problem*
            includes only a partial IP header for some reason, no fields
            of *context* will be filled out.
   
   .. bro:see:: icmp_error_message icmp_unreachable icmp_packet_too_big
      icmp_time_exceeded

.. bro:id:: icmp_redirect

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, tgt: :bro:type:`addr`, dest: :bro:type:`addr`, options: :bro:type:`icmp6_nd_options`)

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
   
   .. bro:see:: icmp_router_solicitation icmp_router_advertisement
      icmp_neighbor_solicitation icmp_neighbor_advertisement

.. bro:id:: icmp_router_advertisement

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, cur_hop_limit: :bro:type:`count`, managed: :bro:type:`bool`, other: :bro:type:`bool`, home_agent: :bro:type:`bool`, pref: :bro:type:`count`, proxy: :bro:type:`bool`, rsv: :bro:type:`count`, router_lifetime: :bro:type:`interval`, reachable_time: :bro:type:`interval`, retrans_timer: :bro:type:`interval`, options: :bro:type:`icmp6_nd_options`)

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
   
   .. bro:see:: icmp_router_solicitation
      icmp_neighbor_solicitation icmp_neighbor_advertisement icmp_redirect

.. bro:id:: icmp_router_solicitation

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, options: :bro:type:`icmp6_nd_options`)

   Generated for ICMP *router solicitation* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. bro:see:: icmp_router_advertisement
      icmp_neighbor_solicitation icmp_neighbor_advertisement icmp_redirect

.. bro:id:: icmp_sent

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`)

   Generated for all ICMP messages that are not handled separately with
   dedicated ICMP events. Bro's ICMP analyzer handles a number of ICMP messages
   directly with dedicated events. This event acts as a fallback for those it
   doesn't.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   
   .. bro:see:: icmp_error_message icmp_sent_payload

.. bro:id:: icmp_sent_payload

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, payload: :bro:type:`string`)

   The same as :bro:see:`icmp_sent` except containing the ICMP payload.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :payload: The payload of the ICMP message.
   
   .. bro:see:: icmp_error_message icmp_sent_payload

.. bro:id:: icmp_time_exceeded

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, code: :bro:type:`count`, context: :bro:type:`icmp_context`)

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
            header from the packet that triggered them, and Bro parses that
            into the *context* structure. Note that if the *exceeded* includes
            only a partial IP header for some reason, no fields of *context*
            will be filled out.
   
   .. bro:see:: icmp_error_message icmp_unreachable icmp_packet_too_big
      icmp_parameter_problem

.. bro:id:: icmp_unreachable

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, code: :bro:type:`count`, context: :bro:type:`icmp_context`)

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
            header from the packet that triggered them, and Bro parses that
            into the *context* structure. Note that if the *unreachable*
            includes only a partial IP header for some reason, no
            fields of *context* will be filled out.
   
   .. bro:see:: icmp_error_message icmp_packet_too_big
      icmp_time_exceeded icmp_parameter_problem


