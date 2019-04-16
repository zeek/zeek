:tocdepth: 3

policy/misc/capture-loss.zeek
=============================
.. bro:namespace:: CaptureLoss

This script logs evidence regarding the degree to which the packet
capture process suffers from measurement loss.  
The loss could be due to overload on the host or NIC performing 
the packet capture or it could even be beyond the host.  If you are 
capturing from a switch with a SPAN port, it's very possible that 
the switch itself could be overloaded and dropping packets.
Reported loss is computed in terms of the number of "gap events" (ACKs 
for a sequence number that's above a gap).

:Namespace: CaptureLoss
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================== ================================================================
:bro:id:`CaptureLoss::too_much_loss`: :bro:type:`double` :bro:attr:`&redef`    The percentage of missed data that is considered "too much" 
                                                                               when the :bro:enum:`CaptureLoss::Too_Much_Loss` notice should be
                                                                               generated.
:bro:id:`CaptureLoss::watch_interval`: :bro:type:`interval` :bro:attr:`&redef` The interval at which capture loss reports are created.
============================================================================== ================================================================

Types
#####
================================================= =
:bro:type:`CaptureLoss::Info`: :bro:type:`record` 
================================================= =

Redefinitions
#############
========================================== =
:bro:type:`Log::ID`: :bro:type:`enum`      
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: CaptureLoss::too_much_loss

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0.1``

   The percentage of missed data that is considered "too much" 
   when the :bro:enum:`CaptureLoss::Too_Much_Loss` notice should be
   generated. The value is expressed as a double between 0 and 1 with 1
   being 100%.

.. bro:id:: CaptureLoss::watch_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``15.0 mins``

   The interval at which capture loss reports are created.

Types
#####
.. bro:type:: CaptureLoss::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp for when the measurement occurred.

      ts_delta: :bro:type:`interval` :bro:attr:`&log`
         The time delay between this measurement and the last.

      peer: :bro:type:`string` :bro:attr:`&log`
         In the event that there are multiple Bro instances logging
         to the same host, this distinguishes each peer with its
         individual name.

      gaps: :bro:type:`count` :bro:attr:`&log`
         Number of missed ACKs from the previous measurement interval.

      acks: :bro:type:`count` :bro:attr:`&log`
         Total number of ACKs seen in the previous measurement interval.

      percent_lost: :bro:type:`double` :bro:attr:`&log`
         Percentage of ACKs seen where the data being ACKed wasn't seen.



