:tocdepth: 3

base/frameworks/config/main.bro
===============================
.. bro:namespace:: Config

The configuration framework provides a way to change Bro options
(as specified by the "option" keyword) at runtime. It also logs runtime
changes to options to config.log.

:Namespace: Config
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`

Summary
~~~~~~~
Types
#####
============================================ ==================================
:bro:type:`Config::Info`: :bro:type:`record` Represents the data in config.log.
============================================ ==================================

Redefinitions
#############
===================================== =====================================
:bro:type:`Log::ID`: :bro:type:`enum` The config logging stream identifier.
===================================== =====================================

Events
######
=============================================== ================================================================
:bro:id:`Config::log_config`: :bro:type:`event` Event that can be handled to access the :bro:type:`Config::Info`
                                                record as it is sent on to the logging framework.
=============================================== ================================================================

Functions
#########
================================================= ==================================================================
:bro:id:`Config::set_value`: :bro:type:`function` This function is the config framework layer around the lower-level
                                                  :bro:see:`Option::set` call.
================================================= ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: Config::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp at which the configuration change occured.

      id: :bro:type:`string` :bro:attr:`&log`
         ID of the value that was changed.

      old_value: :bro:type:`string` :bro:attr:`&log`
         Value before the change.

      new_value: :bro:type:`string` :bro:attr:`&log`
         Value after the change.

      location: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         Optional location that triggered the change.

   Represents the data in config.log.

Events
######
.. bro:id:: Config::log_config

   :Type: :bro:type:`event` (rec: :bro:type:`Config::Info`)

   Event that can be handled to access the :bro:type:`Config::Info`
   record as it is sent on to the logging framework.

Functions
#########
.. bro:id:: Config::set_value

   :Type: :bro:type:`function` (ID: :bro:type:`string`, val: :bro:type:`any`, location: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional` :bro:attr:`&optional`) : :bro:type:`bool`

   This function is the config framework layer around the lower-level
   :bro:see:`Option::set` call. Config::set_value will set the configuration
   value for all nodes in the cluster, no matter where it was called. Note
   that :bro:see:`Option::set` does not distribute configuration changes
   to other nodes.
   

   :ID: The ID of the option to update.
   

   :val: The new value of the option.
   

   :location: Optional parameter detailing where this change originated from.
   

   :returns: true on success, false when an error occurs.


