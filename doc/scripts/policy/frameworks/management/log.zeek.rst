:tocdepth: 3

policy/frameworks/management/log.zeek
=====================================
.. zeek:namespace:: Management::Log

This module implements logging abilities for controller and agent. It uses
Zeek's logging framework and works only for nodes managed by the
supervisor. In this setting Zeek's logging framework operates locally, i.e.,
this does not involve logger nodes.

:Namespace: Management::Log
:Imports: :doc:`policy/frameworks/management/config.zeek </scripts/policy/frameworks/management/config.zeek>`

Summary
~~~~~~~
Types
#####
========================================================================= =========================================================================
:zeek:type:`Management::Log::Info`: :zeek:type:`record` :zeek:attr:`&log` The record type containing the column fields of the agent/controller log.
:zeek:type:`Management::Log::Level`: :zeek:type:`enum`                    The controller/agent log supports four different log levels.
========================================================================= =========================================================================

Redefinitions
#############
======================================= ======================================
:zeek:type:`Log::ID`: :zeek:type:`enum` The cluster logging stream identifier.
                                        
                                        * :zeek:enum:`Management::Log::LOG`
======================================= ======================================

Hooks
#####
==================================================================== =============================================
:zeek:id:`Management::Log::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
==================================================================== =============================================

Functions
#########
========================================================== ===================================
:zeek:id:`Management::Log::debug`: :zeek:type:`function`   A debug-level log message writer.
:zeek:id:`Management::Log::error`: :zeek:type:`function`   An error-level log message writer.
:zeek:id:`Management::Log::info`: :zeek:type:`function`    An info-level log message writer.
:zeek:id:`Management::Log::warning`: :zeek:type:`function` A warning-level log message writer.
========================================================== ===================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Management::Log::Info
   :source-code: policy/frameworks/management/log.zeek 26 37

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         The time at which a cluster message was generated.

      node: :zeek:type:`string` :zeek:attr:`&log`
         The name of the node that is creating the log record.

      level: :zeek:type:`string` :zeek:attr:`&log`
         Log level of this message, converted from the above Level enum

      role: :zeek:type:`string` :zeek:attr:`&log`
         The role of the node, translated from Management::Role.

      message: :zeek:type:`string` :zeek:attr:`&log`
         A message indicating information about cluster controller operation.
   :Attributes: :zeek:attr:`&log`

   The record type containing the column fields of the agent/controller log.

.. zeek:type:: Management::Log::Level
   :source-code: policy/frameworks/management/log.zeek 18 24

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Management::Log::DEBUG Management::Log::Level

      .. zeek:enum:: Management::Log::INFO Management::Log::Level

      .. zeek:enum:: Management::Log::WARNING Management::Log::Level

      .. zeek:enum:: Management::Log::ERROR Management::Log::Level

   The controller/agent log supports four different log levels.

Hooks
#####
.. zeek:id:: Management::Log::log_policy
   :source-code: policy/frameworks/management/log.zeek 15 15

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.

Functions
#########
.. zeek:id:: Management::Log::debug
   :source-code: policy/frameworks/management/log.zeek 85 93

   :Type: :zeek:type:`function` (message: :zeek:type:`string`) : :zeek:type:`void`

   A debug-level log message writer.
   

   :param message: the message to log.
   

.. zeek:id:: Management::Log::error
   :source-code: policy/frameworks/management/log.zeek 115 123

   :Type: :zeek:type:`function` (message: :zeek:type:`string`) : :zeek:type:`void`

   An error-level log message writer. (This only logs a message, it does not
   terminate Zeek or have other runtime effects.)
   

   :param message: the message to log.
   

.. zeek:id:: Management::Log::info
   :source-code: policy/frameworks/management/log.zeek 95 103

   :Type: :zeek:type:`function` (message: :zeek:type:`string`) : :zeek:type:`void`

   An info-level log message writer.
   

   :param message: the message to log.
   

.. zeek:id:: Management::Log::warning
   :source-code: policy/frameworks/management/log.zeek 105 113

   :Type: :zeek:type:`function` (message: :zeek:type:`string`) : :zeek:type:`void`

   A warning-level log message writer.
   

   :param message: the message to log.
   


