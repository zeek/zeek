:tocdepth: 3

base/bif/plugins/Bro_DHCP.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================== ================================
:zeek:id:`dhcp_message`: :zeek:type:`event` Generated for all DHCP messages.
=========================================== ================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: dhcp_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`DHCP::Msg`, options: :zeek:type:`DHCP::Options`)

   Generated for all DHCP messages.
   

   :c: The connection record describing the underlying UDP flow.
   

   :is_orig: Indicate if the message came in a packet from the
           originator/client of the udp flow or the responder/server.
   

   :msg: The parsed type-independent part of the DHCP message. The message
        type is indicated in this record.
   

   :options: The full set of supported and parsed DHCP options.


