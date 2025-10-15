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
========================================================= =============================================================================
:zeek:type:`NetControl::PluginState`: :zeek:type:`record` 
                                                          
                                                          :New Fields: :zeek:type:`NetControl::PluginState`
                                                          
                                                            broker_config: :zeek:type:`NetControl::BrokerConfig` :zeek:attr:`&optional`
                                                              OpenFlow controller for NetControl Broker plugin.
                                                          
                                                            broker_id: :zeek:type:`count` :zeek:attr:`&optional`
                                                              The ID of this broker instance - for the mapping to PluginStates.
========================================================= =============================================================================

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
   :source-code: base/frameworks/netcontrol/plugins/broker.zeek 13 34

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
         

         :param p: Current plugin state.
         

         :param r: The rule to be inserted or removed.
         

         :returns: T if the rule can be handled by the current backend, F otherwise.

   This record specifies the configuration that is passed to :zeek:see:`NetControl::create_broker`.

Events
######
.. zeek:id:: NetControl::broker_add_rule
   :source-code: base/frameworks/netcontrol/plugins/broker.zeek 46 46

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`)


.. zeek:id:: NetControl::broker_remove_rule
   :source-code: base/frameworks/netcontrol/plugins/broker.zeek 47 47

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, reason: :zeek:type:`string`)


.. zeek:id:: NetControl::broker_rule_added
   :source-code: base/frameworks/netcontrol/plugins/broker.zeek 61 72

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, msg: :zeek:type:`string`)


.. zeek:id:: NetControl::broker_rule_error
   :source-code: base/frameworks/netcontrol/plugins/broker.zeek 100 111

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, msg: :zeek:type:`string`)


.. zeek:id:: NetControl::broker_rule_exists
   :source-code: base/frameworks/netcontrol/plugins/broker.zeek 74 85

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, msg: :zeek:type:`string`)


.. zeek:id:: NetControl::broker_rule_removed
   :source-code: base/frameworks/netcontrol/plugins/broker.zeek 87 98

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, msg: :zeek:type:`string`)


.. zeek:id:: NetControl::broker_rule_timeout
   :source-code: base/frameworks/netcontrol/plugins/broker.zeek 113 124

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, i: :zeek:type:`NetControl::FlowInfo`)


Functions
#########
.. zeek:id:: NetControl::create_broker
   :source-code: base/frameworks/netcontrol/plugins/broker.zeek 198 220

   :Type: :zeek:type:`function` (config: :zeek:type:`NetControl::BrokerConfig`, can_expire: :zeek:type:`bool`) : :zeek:type:`NetControl::PluginState`

   Instantiates the broker plugin.


