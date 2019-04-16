:tocdepth: 3

base/bif/plugins/Bro_UDP.events.bif.zeek
========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================= ===============================================================
:bro:id:`udp_contents`: :bro:type:`event`                 Generated for UDP packets to pass on their payload.
:bro:id:`udp_multiple_checksum_errors`: :bro:type:`event` Generated if a UDP flow crosses a checksum-error threshold, per
                                                          'C'/'c' history reporting.
:bro:id:`udp_reply`: :bro:type:`event`                    Generated for each packet sent by a UDP flow's responder.
:bro:id:`udp_request`: :bro:type:`event`                  Generated for each packet sent by a UDP flow's originator.
========================================================= ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: udp_contents

   :Type: :bro:type:`event` (u: :bro:type:`connection`, is_orig: :bro:type:`bool`, contents: :bro:type:`string`)

   Generated for UDP packets to pass on their payload. As the number of UDP
   packets can be very large, this event is normally raised only for those on
   ports configured in :bro:id:`udp_content_delivery_ports_orig` (for packets
   sent by the flow's originator) or :bro:id:`udp_content_delivery_ports_resp`
   (for packets sent by the flow's responder). However, delivery can be enabled
   for all UDP request and reply packets by setting
   :bro:id:`udp_content_deliver_all_orig` or
   :bro:id:`udp_content_deliver_all_resp`, respectively. Note that this
   event is also raised for all matching UDP packets, including empty ones.
   

   :u: The connection record for the corresponding UDP flow.
   

   :is_orig: True if the event is raised for the originator side.
   

   :contents: TODO.
   
   .. bro:see::  udp_reply udp_request udp_session_done
      udp_content_deliver_all_orig udp_content_deliver_all_resp
      udp_content_delivery_ports_orig udp_content_delivery_ports_resp

.. bro:id:: udp_multiple_checksum_errors

   :Type: :bro:type:`event` (u: :bro:type:`connection`, is_orig: :bro:type:`bool`, threshold: :bro:type:`count`)

   Generated if a UDP flow crosses a checksum-error threshold, per
   'C'/'c' history reporting.
   

   :u: The connection record for the corresponding UDP flow.
   

   :is_orig: True if the event is raised for the originator side.
   

   :threshold: the threshold that was crossed
   
   .. bro:see::  udp_reply udp_request udp_session_done
      tcp_multiple_checksum_errors

.. bro:id:: udp_reply

   :Type: :bro:type:`event` (u: :bro:type:`connection`)

   Generated for each packet sent by a UDP flow's responder. This a potentially
   expensive event due to the volume of UDP traffic and should be used with
   care.
   

   :u: The connection record for the corresponding UDP flow.
   
   .. bro:see:: udp_contents  udp_request udp_session_done

.. bro:id:: udp_request

   :Type: :bro:type:`event` (u: :bro:type:`connection`)

   Generated for each packet sent by a UDP flow's originator. This a potentially
   expensive event due to the volume of UDP traffic and should be used with
   care.
   

   :u: The connection record for the corresponding UDP flow.
   
   .. bro:see:: udp_contents udp_reply  udp_session_done


