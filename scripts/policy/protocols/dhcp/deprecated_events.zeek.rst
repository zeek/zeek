:tocdepth: 3

policy/protocols/dhcp/deprecated_events.zeek
============================================

Bro 2.6 removed certain DHCP events, but scripts in the Bro
ecosystem are still relying on those events. As a transition, this
script will handle the new event, and generate the old events,
which are marked as deprecated.  Note: This script should be
removed in the next Bro version after 2.6.

:Imports: :doc:`base/protocols/dhcp </scripts/base/protocols/dhcp/index>`

Summary
~~~~~~~
Types
#####
================================================= ====================================================
:zeek:type:`dhcp_msg`: :zeek:type:`record`        A DHCP message.
:zeek:type:`dhcp_router_list`: :zeek:type:`table` A list of router addresses offered by a DHCP server.
================================================= ====================================================

Events
######
===================================================================== ===================================================================================
:zeek:id:`dhcp_ack`: :zeek:type:`event` :zeek:attr:`&deprecated`      Generated for DHCP messages of type *DHCPACK* (Server to client with configuration
                                                                      parameters, including committed network address).
:zeek:id:`dhcp_decline`: :zeek:type:`event` :zeek:attr:`&deprecated`  Generated for DHCP messages of type *DHCPDECLINE* (Client to server indicating
                                                                      network address is already in use).
:zeek:id:`dhcp_discover`: :zeek:type:`event` :zeek:attr:`&deprecated` Generated for DHCP messages of type *DHCPDISCOVER* (client broadcast to locate
                                                                      available servers).
:zeek:id:`dhcp_inform`: :zeek:type:`event` :zeek:attr:`&deprecated`   Generated for DHCP messages of type *DHCPINFORM* (Client to server, asking only for
                                                                      local configuration parameters; client already has externally configured network
                                                                      address).
:zeek:id:`dhcp_nak`: :zeek:type:`event` :zeek:attr:`&deprecated`      Generated for DHCP messages of type *DHCPNAK* (Server to client indicating client's
                                                                      notion of network address is incorrect (e.g., client has moved to new subnet) or
                                                                      client's lease has expired).
:zeek:id:`dhcp_offer`: :zeek:type:`event` :zeek:attr:`&deprecated`    Generated for DHCP messages of type *DHCPOFFER* (server to client in response
                                                                      to DHCPDISCOVER with offer of configuration parameters).
:zeek:id:`dhcp_release`: :zeek:type:`event` :zeek:attr:`&deprecated`  Generated for DHCP messages of type *DHCPRELEASE* (Client to server relinquishing
                                                                      network address and cancelling remaining lease).
:zeek:id:`dhcp_request`: :zeek:type:`event` :zeek:attr:`&deprecated`  Generated for DHCP messages of type *DHCPREQUEST* (Client message to servers either
                                                                      (a) requesting offered parameters from one server and implicitly declining offers
                                                                      from all others, (b) confirming correctness of previously allocated address after,
                                                                      e.g., system reboot, or (c) extending the lease on a particular network address.)
===================================================================== ===================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: dhcp_msg

   :Type: :zeek:type:`record`

      op: :zeek:type:`count`
         Message OP code. 1 = BOOTREQUEST, 2 = BOOTREPLY

      m_type: :zeek:type:`count`
         The type of DHCP message.

      xid: :zeek:type:`count`
         Transaction ID of a DHCP session.

      h_addr: :zeek:type:`string`
         Hardware address of the client.

      ciaddr: :zeek:type:`addr`
         Original IP address of the client.

      yiaddr: :zeek:type:`addr`
         IP address assigned to the client.

   A DHCP message.
   
   .. note:: This type is included to support the deprecated events dhcp_ack,
             dhcp_decline, dhcp_discover, dhcp_inform, dhcp_nak, dhcp_offer,
             dhcp_release and dhcp_request and is thus similarly deprecated
             itself. Use :zeek:see:`dhcp_message` instead.
   
   .. zeek:see:: dhcp_message dhcp_ack dhcp_decline dhcp_discover
                dhcp_inform dhcp_nak dhcp_offer dhcp_release dhcp_request

.. zeek:type:: dhcp_router_list

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`addr`

   A list of router addresses offered by a DHCP server.
   
   .. note:: This type is included to support the deprecated events dhcp_ack
             and dhcp_offer and is thus similarly deprecated
             itself. Use :zeek:see:`dhcp_message` instead.
   
   .. zeek:see:: dhcp_message dhcp_ack dhcp_offer

Events
######
.. zeek:id:: dhcp_ack

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dhcp_msg`, mask: :zeek:type:`addr`, router: :zeek:type:`dhcp_router_list`, lease: :zeek:type:`interval`, serv_addr: :zeek:type:`addr`, host_name: :zeek:type:`string`)
   :Attributes: :zeek:attr:`&deprecated`

   Generated for DHCP messages of type *DHCPACK* (Server to client with configuration
   parameters, including committed network address).
   

   :c: The connection record describing the underlying UDP flow.
   

   :msg: The parsed type-independent part of the DHCP message.
   

   :mask: The subnet mask specified by the message.
   

   :router: The list of routers specified by the message.
   

   :lease: The least interval specified by the message.
   

   :serv_addr: The server address specified by the message.
   

   :host_name: Optional host name value. May differ from the host name requested
              from the client.
   
   .. zeek:see:: dhcp_message dhcp_discover dhcp_offer dhcp_request
                dhcp_decline dhcp_nak dhcp_release dhcp_inform
   
   .. note:: This event has been deprecated, and will be removed in the next version.
      Use dhcp_message instead.
   

.. zeek:id:: dhcp_decline

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dhcp_msg`, host_name: :zeek:type:`string`)
   :Attributes: :zeek:attr:`&deprecated`

   Generated for DHCP messages of type *DHCPDECLINE* (Client to server indicating
   network address is already in use).
   

   :c: The connection record describing the underlying UDP flow.
   

   :msg: The parsed type-independent part of the DHCP message.
   

   :host_name: Optional host name value.
   
   .. zeek:see:: dhcp_message dhcp_discover dhcp_offer dhcp_request
                dhcp_ack dhcp_nak dhcp_release dhcp_inform
   
   .. note:: This event has been deprecated, and will be removed in the next version.
      Use dhcp_message instead.
   
   .. note:: Bro does not support broadcast packets (as used by the DHCP
      protocol). It treats broadcast addresses just like any other and
      associates packets into transport-level flows in the same way as usual.
   

.. zeek:id:: dhcp_discover

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dhcp_msg`, req_addr: :zeek:type:`addr`, host_name: :zeek:type:`string`)
   :Attributes: :zeek:attr:`&deprecated`

   Generated for DHCP messages of type *DHCPDISCOVER* (client broadcast to locate
   available servers).
   

   :c: The connection record describing the underlying UDP flow.
   

   :msg: The parsed type-independent part of the DHCP message.
   

   :req_addr: The specific address requested by the client.
   

   :host_name: The value of the host name option, if specified by the client.
   
   .. zeek:see:: dhcp_message dhcp_discover dhcp_offer dhcp_request
                dhcp_decline dhcp_ack dhcp_nak dhcp_release dhcp_inform
   
   .. note:: This event has been deprecated, and will be removed in the next version.
      Use dhcp_message instead.
   
   .. note:: Bro does not support broadcast packets (as used by the DHCP
      protocol). It treats broadcast addresses just like any other and
      associates packets into transport-level flows in the same way as usual.
   

.. zeek:id:: dhcp_inform

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dhcp_msg`, host_name: :zeek:type:`string`)
   :Attributes: :zeek:attr:`&deprecated`

   Generated for DHCP messages of type *DHCPINFORM* (Client to server, asking only for
   local configuration parameters; client already has externally configured network
   address).
   

   :c: The connection record describing the underlying UDP flow.
   

   :msg: The parsed type-independent part of the DHCP message.
   

   :host_name: The value of the host name option, if specified by the client.
   
   .. zeek:see:: dhcp_message dhcp_discover dhcp_offer dhcp_request
                dhcp_decline dhcp_ack dhcp_nak dhcp_release
   
   .. note:: This event has been deprecated, and will be removed in the next version.
      Use dhcp_message instead.
   
   .. note:: Bro does not support broadcast packets (as used by the DHCP
      protocol). It treats broadcast addresses just like any other and
      associates packets into transport-level flows in the same way as usual.
   

.. zeek:id:: dhcp_nak

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dhcp_msg`, host_name: :zeek:type:`string`)
   :Attributes: :zeek:attr:`&deprecated`

   Generated for DHCP messages of type *DHCPNAK* (Server to client indicating client's
   notion of network address is incorrect (e.g., client has moved to new subnet) or
   client's lease has expired).
   

   :c: The connection record describing the underlying UDP flow.
   

   :msg: The parsed type-independent part of the DHCP message.
   

   :host_name: Optional host name value.
   
   .. zeek:see:: dhcp_message dhcp_discover dhcp_offer dhcp_request
                dhcp_decline dhcp_ack dhcp_release dhcp_inform
   
   .. note:: This event has been deprecated, and will be removed in the next version.
      Use dhcp_message instead.
   
   .. note:: Bro does not support broadcast packets (as used by the DHCP
      protocol). It treats broadcast addresses just like any other and
      associates packets into transport-level flows in the same way as usual.
   

.. zeek:id:: dhcp_offer

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dhcp_msg`, mask: :zeek:type:`addr`, router: :zeek:type:`dhcp_router_list`, lease: :zeek:type:`interval`, serv_addr: :zeek:type:`addr`, host_name: :zeek:type:`string`)
   :Attributes: :zeek:attr:`&deprecated`

   Generated for DHCP messages of type *DHCPOFFER* (server to client in response
   to DHCPDISCOVER with offer of configuration parameters).
   

   :c: The connection record describing the underlying UDP flow.
   

   :msg: The parsed type-independent part of the DHCP message.
   

   :mask: The subnet mask specified by the message.
   

   :router: The list of routers specified by the message.
   

   :lease: The least interval specified by the message.
   

   :serv_addr: The server address specified by the message.
   

   :host_name: Optional host name value. May differ from the host name requested
              from the client.
   
   .. zeek:see:: dhcp_message dhcp_discover dhcp_request dhcp_decline
                dhcp_ack dhcp_nak dhcp_release dhcp_inform
   
   .. note:: This event has been deprecated, and will be removed in the next version.
      Use dhcp_message instead.
   
   .. note:: Bro does not support broadcast packets (as used by the DHCP
      protocol). It treats broadcast addresses just like any other and
      associates packets into transport-level flows in the same way as usual.
   

.. zeek:id:: dhcp_release

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dhcp_msg`, host_name: :zeek:type:`string`)
   :Attributes: :zeek:attr:`&deprecated`

   Generated for DHCP messages of type *DHCPRELEASE* (Client to server relinquishing
   network address and cancelling remaining lease).
   

   :c: The connection record describing the underlying UDP flow.
   

   :msg: The parsed type-independent part of the DHCP message.
   

   :host_name: The value of the host name option, if specified by the client.
   
   .. zeek:see:: dhcp_message dhcp_discover dhcp_offer dhcp_request
                dhcp_decline dhcp_ack dhcp_nak dhcp_inform
   
   .. note:: This event has been deprecated, and will be removed in the next version.
      Use dhcp_message instead.
   

.. zeek:id:: dhcp_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dhcp_msg`, req_addr: :zeek:type:`addr`, serv_addr: :zeek:type:`addr`, host_name: :zeek:type:`string`)
   :Attributes: :zeek:attr:`&deprecated`

   Generated for DHCP messages of type *DHCPREQUEST* (Client message to servers either
   (a) requesting offered parameters from one server and implicitly declining offers
   from all others, (b) confirming correctness of previously allocated address after,
   e.g., system reboot, or (c) extending the lease on a particular network address.)
   

   :c: The connection record describing the underlying UDP flow.
   

   :msg: The parsed type-independent part of the DHCP message.
   

   :req_addr: The client address specified by the message.
   

   :serv_addr: The server address specified by the message.
   

   :host_name: The value of the host name option, if specified by the client.
   
   .. zeek:see:: dhcp_message dhcp_discover dhcp_offer dhcp_decline
      	       dhcp_ack dhcp_nak dhcp_release dhcp_inform
   
   .. note:: This event has been deprecated, and will be removed in the next version.
      Use dhcp_message instead.
   
   .. note:: Bro does not support broadcast packets (as used by the DHCP
      protocol). It treats broadcast addresses just like any other and
      associates packets into transport-level flows in the same way as usual.
   


