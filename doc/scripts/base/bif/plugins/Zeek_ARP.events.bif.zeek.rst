:tocdepth: 3

base/bif/plugins/Zeek_ARP.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================== =====================================================
:zeek:id:`arp_reply`: :zeek:type:`event`   Generated for ARP replies.
:zeek:id:`arp_request`: :zeek:type:`event` Generated for ARP requests.
:zeek:id:`bad_arp`: :zeek:type:`event`     Generated for ARP packets that Zeek cannot interpret.
========================================== =====================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: arp_reply
   :source-code: base/bif/plugins/Zeek_ARP.events.bif.zeek 43 43

   :Type: :zeek:type:`event` (mac_src: :zeek:type:`string`, mac_dst: :zeek:type:`string`, SPA: :zeek:type:`addr`, SHA: :zeek:type:`string`, TPA: :zeek:type:`addr`, THA: :zeek:type:`string`)

   Generated for ARP replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Address_Resolution_Protocol>`__
   for more information about the ARP protocol.
   

   :param mac_src: The reply's source MAC address.
   

   :param mac_dst: The reply's destination MAC address.
   

   :param SPA: The sender protocol address.
   

   :param SHA: The sender hardware address.
   

   :param TPA: The target protocol address.
   

   :param THA: The target hardware address.
   
   .. zeek:see::  arp_request bad_arp

.. zeek:id:: arp_request
   :source-code: base/bif/plugins/Zeek_ARP.events.bif.zeek 22 22

   :Type: :zeek:type:`event` (mac_src: :zeek:type:`string`, mac_dst: :zeek:type:`string`, SPA: :zeek:type:`addr`, SHA: :zeek:type:`string`, TPA: :zeek:type:`addr`, THA: :zeek:type:`string`)

   Generated for ARP requests.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Address_Resolution_Protocol>`__
   for more information about the ARP protocol.
   

   :param mac_src: The request's source MAC address.
   

   :param mac_dst: The request's destination MAC address.
   

   :param SPA: The sender protocol address.
   

   :param SHA: The sender hardware address.
   

   :param TPA: The target protocol address.
   

   :param THA: The target hardware address.
   
   .. zeek:see:: arp_reply  bad_arp

.. zeek:id:: bad_arp
   :source-code: base/bif/plugins/Zeek_ARP.events.bif.zeek 66 66

   :Type: :zeek:type:`event` (SPA: :zeek:type:`addr`, SHA: :zeek:type:`string`, TPA: :zeek:type:`addr`, THA: :zeek:type:`string`, explanation: :zeek:type:`string`)

   Generated for ARP packets that Zeek cannot interpret. Examples are packets
   with non-standard hardware address formats or hardware addresses that do not
   match the originator of the packet.
   

   :param SPA: The sender protocol address.
   

   :param SHA: The sender hardware address.
   

   :param TPA: The target protocol address.
   

   :param THA: The target hardware address.
   

   :param explanation: A short description of why the ARP packet is considered "bad".
   
   .. zeek:see:: arp_reply arp_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


