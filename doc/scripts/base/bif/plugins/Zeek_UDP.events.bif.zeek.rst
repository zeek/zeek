:tocdepth: 3

base/bif/plugins/Zeek_UDP.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================================== ===============================================================
:zeek:id:`udp_contents`: :zeek:type:`event`                 Generated for UDP packets to pass on their payload.
:zeek:id:`udp_multiple_checksum_errors`: :zeek:type:`event` Generated if a UDP flow crosses a checksum-error threshold, per
                                                            'C'/'c' history reporting.
:zeek:id:`udp_reply`: :zeek:type:`event`                    Generated for each packet sent by a UDP flow's responder.
:zeek:id:`udp_request`: :zeek:type:`event`                  Generated for each packet sent by a UDP flow's originator.
=========================================================== ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: udp_contents
   :source-code: base/bif/plugins/Zeek_UDP.events.bif.zeek 43 43

   :Type: :zeek:type:`event` (u: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, contents: :zeek:type:`string`)

   Generated for UDP packets to pass on their payload. As the number of UDP
   packets can be very large, this event is normally raised only for those on
   ports configured in :zeek:id:`udp_content_delivery_ports_orig` (for packets
   sent by the flow's originator) or :zeek:id:`udp_content_delivery_ports_resp`
   (for packets sent by the flow's responder). However, delivery can be enabled
   for all UDP request and reply packets by setting
   :zeek:id:`udp_content_deliver_all_orig` or
   :zeek:id:`udp_content_deliver_all_resp`, respectively. Note that this
   event is also raised for all matching UDP packets, including empty ones.
   

   :param u: The connection record for the corresponding UDP flow.
   

   :param is_orig: True if the event is raised for the originator side.
   

   :param contents: TODO.
   
   .. zeek:see::  udp_reply udp_request udp_session_done
      udp_content_deliver_all_orig udp_content_deliver_all_resp
      udp_content_delivery_ports_orig udp_content_delivery_ports_resp

.. zeek:id:: udp_multiple_checksum_errors
   :source-code: base/bif/plugins/Zeek_UDP.events.bif.zeek 57 57

   :Type: :zeek:type:`event` (u: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, threshold: :zeek:type:`count`)

   Generated if a UDP flow crosses a checksum-error threshold, per
   'C'/'c' history reporting.
   

   :param u: The connection record for the corresponding UDP flow.
   

   :param is_orig: True if the event is raised for the originator side.
   

   :param threshold: the threshold that was crossed
   
   .. zeek:see::  udp_reply udp_request udp_session_done
      tcp_multiple_checksum_errors

.. zeek:id:: udp_reply
   :source-code: base/bif/plugins/Zeek_UDP.events.bif.zeek 21 21

   :Type: :zeek:type:`event` (u: :zeek:type:`connection`)

   Generated for each packet sent by a UDP flow's responder. This a potentially
   expensive event due to the volume of UDP traffic and should be used with
   care.
   

   :param u: The connection record for the corresponding UDP flow.
   
   .. zeek:see:: udp_contents  udp_request udp_session_done

.. zeek:id:: udp_request
   :source-code: base/bif/plugins/Zeek_UDP.events.bif.zeek 11 11

   :Type: :zeek:type:`event` (u: :zeek:type:`connection`)

   Generated for each packet sent by a UDP flow's originator. This a potentially
   expensive event due to the volume of UDP traffic and should be used with
   care.
   

   :param u: The connection record for the corresponding UDP flow.
   
   .. zeek:see:: udp_contents udp_reply  udp_session_done


