:tocdepth: 3

base/frameworks/netcontrol/plugins/broker.zeek
==============================================
.. zeek:namespace:: NetControl

Broker plugin for the NetControl framework. Sends the raw data structures
used in NetControl on to Broker to allow for easy handling, e.g., of
command-line scripts.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/frameworks/netcontrol/main.zeek </scripts/base/frameworks/netcontrol/main.zeek>`, :doc:`base/frameworks/netcontrol/plugin.zeek </scripts/base/frameworks/netcontrol/plugin.zeek>`

Summary
~~~~~~~
Types
#####
========================================================== ================================================================================================
:zeek:type:`NetControl::BrokerConfig`: :zeek:type:`record` This record specifies the configuration that is passed to :zeek:see:`NetControl::create_broker`.
========================================================== ================================================================================================

Redefinitions
#############
========================================================= =
:zeek:type:`NetControl::PluginState`: :zeek:type:`record` 
========================================================= =

Events
######
============================================================== =
:zeek:id:`NetControl::broker_add_rule`: :zeek:type:`event`     
:zeek:id:`NetControl::broker_remove_rule`: :zeek:type:`event`  
:zeek:id:`NetControl::broker_rule_added`: :zeek:type:`event`   
:zeek:id:`NetControl::broker_rule_error`: :zeek:type:`event`   
:zeek:id:`NetControl::broker_rule_exists`: :zeek:type:`event`  
:zeek:id:`NetControl::broker_rule_removed`: :zeek:type:`event` 
:zeek:id:`NetControl::broker_rule_timeout`: :zeek:type:`event` 
============================================================== =

Functions
#########
=========================================================== ===============================
:zeek:id:`NetControl::create_broker`: :zeek:type:`function` Instantiates the broker plugin.
=========================================================== ===============================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: NetControl::BrokerConfig

   :Type: :zeek:type:`record`

      topic: :zeek:type:`string` :zeek:attr:`&optional`
         The broker topic to send events to.

      host: :zeek:type:`addr` :zeek:attr:`&optional`
         Broker host to connect to.

      bport: :zeek:type:`port` :zeek:attr:`&optional`
         Broker port to connect to.

      monitor: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         Do we accept rules for the monitor path? Default true.

      forward: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         Do we accept rules for the forward path? Default true.

      check_pred: :zeek:type:`function` (p: :zeek:type:`NetControl::PluginState`, r: :zeek:type:`NetControl::Rule`) : :zeek:type:`bool` :zeek:attr:`&optional`
         Predicate that is called on rule insertion or removal.
         

         :p: Current plugin state.
         

         :r: The rule to be inserted or removed.
         

         :returns: T if the rule can be handled by the current backend, F otherwise.

   This record specifies the configuration that is passed to :zeek:see:`NetControl::create_broker`.

Events
######
.. zeek:id:: NetControl::broker_add_rule

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`)


.. zeek:id:: NetControl::broker_remove_rule

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, reason: :zeek:type:`string`)


.. zeek:id:: NetControl::broker_rule_added

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, msg: :zeek:type:`string`)


.. zeek:id:: NetControl::broker_rule_error

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, msg: :zeek:type:`string`)


.. zeek:id:: NetControl::broker_rule_exists

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, msg: :zeek:type:`string`)


.. zeek:id:: NetControl::broker_rule_removed

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, msg: :zeek:type:`string`)


.. zeek:id:: NetControl::broker_rule_timeout

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, i: :zeek:type:`NetControl::FlowInfo`)


Functions
#########
.. zeek:id:: NetControl::create_broker

   :Type: :zeek:type:`function` (config: :zeek:type:`NetControl::BrokerConfig`, can_expire: :zeek:type:`bool`) : :zeek:type:`NetControl::PluginState`

   Instantiates the broker plugin.


