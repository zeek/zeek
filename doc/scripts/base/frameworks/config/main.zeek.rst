:tocdepth: 3

base/frameworks/config/main.zeek
================================
.. zeek:namespace:: Config

The configuration framework provides a way to change Zeek options
(as specified by the "option" keyword) at runtime. It also logs runtime
changes to options to config.log.

:Namespace: Config
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`

Summary
~~~~~~~
Types
#####
============================================== ==================================
:zeek:type:`Config::Info`: :zeek:type:`record` Represents the data in config.log.
============================================== ==================================

Redefinitions
#############
======================================= =====================================
:zeek:type:`Log::ID`: :zeek:type:`enum` The config logging stream identifier.
                                        
                                        * :zeek:enum:`Config::LOG`
======================================= =====================================

Events
######
================================================= =================================================================
:zeek:id:`Config::log_config`: :zeek:type:`event` Event that can be handled to access the :zeek:type:`Config::Info`
                                                  record as it is sent on to the logging framework.
================================================= =================================================================

Hooks
#####
=========================================================== =============================================
:zeek:id:`Config::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
=========================================================== =============================================

Functions
#########
=================================================== ==================================================================
:zeek:id:`Config::set_value`: :zeek:type:`function` This function is the config framework layer around the lower-level
                                                    :zeek:see:`Option::set` call.
=================================================== ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Config::Info
   :source-code: base/frameworks/config/main.zeek 17 28

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp at which the configuration change occurred.

      id: :zeek:type:`string` :zeek:attr:`&log`
         ID of the value that was changed.

      old_value: :zeek:type:`string` :zeek:attr:`&log`
         Value before the change.

      new_value: :zeek:type:`string` :zeek:attr:`&log`
         Value after the change.

      location: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         Optional location that triggered the change.

   Represents the data in config.log.

Events
######
.. zeek:id:: Config::log_config
   :source-code: base/frameworks/config/main.zeek 32 32

   :Type: :zeek:type:`event` (rec: :zeek:type:`Config::Info`)

   Event that can be handled to access the :zeek:type:`Config::Info`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: Config::log_policy
   :source-code: base/frameworks/config/main.zeek 14 14

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.

Functions
#########
.. zeek:id:: Config::set_value
   :source-code: base/frameworks/config/main.zeek 99 102

   :Type: :zeek:type:`function` (ID: :zeek:type:`string`, val: :zeek:type:`any`, location: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   This function is the config framework layer around the lower-level
   :zeek:see:`Option::set` call. Config::set_value will set the configuration
   value for all nodes in the cluster, no matter where it was called. Note
   that :zeek:see:`Option::set` does not distribute configuration changes
   to other nodes.
   

   :param ID: The ID of the option to update.
   

   :param val: The new value of the option.
   

   :param location: Optional parameter detailing where this change originated from.
   

   :returns: true on success, false when an error occurs.


