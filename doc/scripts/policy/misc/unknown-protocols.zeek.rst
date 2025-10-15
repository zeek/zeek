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
   :source-code: policy/misc/unknown-protocols.zeek 15 28

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp for when the measurement occurred.

      analyzer: :zeek:type:`string` :zeek:attr:`&log`
         The string name of the analyzer attempting to forward the protocol.

      protocol_id: :zeek:type:`string` :zeek:attr:`&log`
         The identifier of the protocol being forwarded.

      first_bytes: :zeek:type:`string` :zeek:attr:`&log`
         A certain number of bytes at the start of the unknown protocol's
         header.


Hooks
#####
.. zeek:id:: UnknownProtocol::log_policy
   :source-code: policy/misc/unknown-protocols.zeek 13 13

   :Type: :zeek:type:`Log::PolicyHook`



