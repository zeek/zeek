:tocdepth: 3

policy/misc/unknown-protocols.zeek
==================================
.. zeek:namespace:: UnknownProtocol

This script logs information about packet protocols that Zeek doesn't
know how to process. Mostly these come from packet analysis plugins when
they attempt to forward to the next analyzer, but they also can originate
from non-packet analyzers.

:Namespace: UnknownProtocol
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`

Summary
~~~~~~~
Types
#####
======================================================= =
:zeek:type:`UnknownProtocol::Info`: :zeek:type:`record`
======================================================= =

Redefinitions
#############
======================================= ===================================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                        * :zeek:enum:`UnknownProtocol::LOG`
======================================= ===================================

Hooks
#####
==================================================================== =
:zeek:id:`UnknownProtocol::log_policy`: :zeek:type:`Log::PolicyHook`
==================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: UnknownProtocol::Info
   :source-code: policy/misc/unknown-protocols.zeek 15 38

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the measurement occurred.


   .. zeek:field:: analyzer :zeek:type:`string` :zeek:attr:`&log`

      The string name of the analyzer attempting to forward the protocol.


   .. zeek:field:: protocol_id :zeek:type:`string` :zeek:attr:`&log`

      The identifier of the protocol being forwarded in hex notation.


   .. zeek:field:: protocol_id_num :zeek:type:`count`

      The identifier of the protocol being forwarded as count.
      Note: The count value is not logged by default. It is provided for
      easy access in log policy hooks.


   .. zeek:field:: first_bytes :zeek:type:`string` :zeek:attr:`&log`

      A certain number of bytes at the start of the unknown protocol's
      header.


   .. zeek:field:: analyzer_history :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log`

      The chain of packet analyzers that processed the packet up to this
      point. This includes the history of encapsulating packets in case
      of tunneling.



Hooks
#####
.. zeek:id:: UnknownProtocol::log_policy
   :source-code: policy/misc/unknown-protocols.zeek 13 13

   :Type: :zeek:type:`Log::PolicyHook`



