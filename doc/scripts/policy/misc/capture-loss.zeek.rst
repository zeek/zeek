:tocdepth: 3

policy/misc/capture-loss.zeek
=============================
.. zeek:namespace:: CaptureLoss

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
========================================================================================= =================================================================
:zeek:id:`CaptureLoss::initial_watch_interval`: :zeek:type:`interval` :zeek:attr:`&redef` For faster feedback on cluster health, the first capture loss
                                                                                          report is generated this many minutes after startup.
:zeek:id:`CaptureLoss::minimum_acks`: :zeek:type:`count` :zeek:attr:`&redef`              The minimum number of ACKs expected for a single peer in a
                                                                                          watch interval.
:zeek:id:`CaptureLoss::too_much_loss`: :zeek:type:`double` :zeek:attr:`&redef`            The percentage of missed data that is considered "too much"
                                                                                          when the :zeek:enum:`CaptureLoss::Too_Much_Loss` notice should be
                                                                                          generated.
:zeek:id:`CaptureLoss::watch_interval`: :zeek:type:`interval` :zeek:attr:`&redef`         The interval at which capture loss reports are created in a
                                                                                          running cluster (that is, after the first report).
========================================================================================= =================================================================

Types
#####
=================================================== =
:zeek:type:`CaptureLoss::Info`: :zeek:type:`record` 
=================================================== =

Redefinitions
#############
============================================ =============================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      
                                             
                                             * :zeek:enum:`CaptureLoss::LOG`
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`CaptureLoss::Too_Little_Traffic`:
                                               Report if the traffic seen by a peer within a given watch
                                               interval is less than :zeek:id:`CaptureLoss::minimum_acks`.
                                             
                                             * :zeek:enum:`CaptureLoss::Too_Much_Loss`:
                                               Report if the detected capture loss exceeds the percentage
                                               threshold defined in :zeek:id:`CaptureLoss::too_much_loss`.
============================================ =============================================================

Hooks
#####
================================================================ =
:zeek:id:`CaptureLoss::log_policy`: :zeek:type:`Log::PolicyHook` 
================================================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: CaptureLoss::initial_watch_interval
   :source-code: policy/misc/capture-loss.zeek 51 51

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 min``

   For faster feedback on cluster health, the first capture loss
   report is generated this many minutes after startup.

.. zeek:id:: CaptureLoss::minimum_acks
   :source-code: policy/misc/capture-loss.zeek 62 62

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1``

   The minimum number of ACKs expected for a single peer in a
   watch interval. If the number seen is less than this,
   :zeek:enum:`CaptureLoss::Too_Little_Traffic` is raised.

.. zeek:id:: CaptureLoss::too_much_loss
   :source-code: policy/misc/capture-loss.zeek 57 57

   :Type: :zeek:type:`double`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0.1``

   The percentage of missed data that is considered "too much"
   when the :zeek:enum:`CaptureLoss::Too_Much_Loss` notice should be
   generated. The value is expressed as a double between 0 and 1 with 1
   being 100%.

.. zeek:id:: CaptureLoss::watch_interval
   :source-code: policy/misc/capture-loss.zeek 47 47

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``15.0 mins``

   The interval at which capture loss reports are created in a
   running cluster (that is, after the first report).

Types
#####
.. zeek:type:: CaptureLoss::Info
   :source-code: policy/misc/capture-loss.zeek 28 43

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp for when the measurement occurred.

      ts_delta: :zeek:type:`interval` :zeek:attr:`&log`
         The time delay between this measurement and the last.

      peer: :zeek:type:`string` :zeek:attr:`&log`
         In the event that there are multiple Zeek instances logging
         to the same host, this distinguishes each peer with its
         individual name.

      gaps: :zeek:type:`count` :zeek:attr:`&log`
         Number of missed ACKs from the previous measurement interval.

      acks: :zeek:type:`count` :zeek:attr:`&log`
         Total number of ACKs seen in the previous measurement interval.

      percent_lost: :zeek:type:`double` :zeek:attr:`&log`
         Percentage of ACKs seen where the data being ACKed wasn't seen.


Hooks
#####
.. zeek:id:: CaptureLoss::log_policy
   :source-code: policy/misc/capture-loss.zeek 17 17

   :Type: :zeek:type:`Log::PolicyHook`



