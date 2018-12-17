:tocdepth: 3

base/frameworks/netcontrol/plugins/broker.bro
=============================================
.. bro:namespace:: NetControl

Broker plugin for the NetControl framework. Sends the raw data structures
used in NetControl on to Broker to allow for easy handling, e.g., of
command-line scripts.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/frameworks/netcontrol/main.bro </scripts/base/frameworks/netcontrol/main.bro>`, :doc:`base/frameworks/netcontrol/plugin.bro </scripts/base/frameworks/netcontrol/plugin.bro>`

Summary
~~~~~~~
Types
#####
======================================================== ===============================================================================================
:bro:type:`NetControl::BrokerConfig`: :bro:type:`record` This record specifies the configuration that is passed to :bro:see:`NetControl::create_broker`.
======================================================== ===============================================================================================

Redefinitions
#############
======================================================= =
:bro:type:`NetControl::PluginState`: :bro:type:`record` 
======================================================= =

Events
######
============================================================ =
:bro:id:`NetControl::broker_add_rule`: :bro:type:`event`     
:bro:id:`NetControl::broker_remove_rule`: :bro:type:`event`  
:bro:id:`NetControl::broker_rule_added`: :bro:type:`event`   
:bro:id:`NetControl::broker_rule_error`: :bro:type:`event`   
:bro:id:`NetControl::broker_rule_exists`: :bro:type:`event`  
:bro:id:`NetControl::broker_rule_removed`: :bro:type:`event` 
:bro:id:`NetControl::broker_rule_timeout`: :bro:type:`event` 
============================================================ =

Functions
#########
========================================================= ===============================
:bro:id:`NetControl::create_broker`: :bro:type:`function` Instantiates the broker plugin.
========================================================= ===============================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: NetControl::BrokerConfig

   :Type: :bro:type:`record`

      topic: :bro:type:`string` :bro:attr:`&optional`
         The broker topic to send events to.

      host: :bro:type:`addr` :bro:attr:`&optional`
         Broker host to connect to.

      bport: :bro:type:`port` :bro:attr:`&optional`
         Broker port to connect to.

      monitor: :bro:type:`bool` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         Do we accept rules for the monitor path? Default true.

      forward: :bro:type:`bool` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         Do we accept rules for the forward path? Default true.

      check_pred: :bro:type:`function` (p: :bro:type:`NetControl::PluginState`, r: :bro:type:`NetControl::Rule`) : :bro:type:`bool` :bro:attr:`&optional`
         Predicate that is called on rule insertion or removal.
         

         :p: Current plugin state.
         

         :r: The rule to be inserted or removed.
         

         :returns: T if the rule can be handled by the current backend, F otherwise.

   This record specifies the configuration that is passed to :bro:see:`NetControl::create_broker`.

Events
######
.. bro:id:: NetControl::broker_add_rule

   :Type: :bro:type:`event` (id: :bro:type:`count`, r: :bro:type:`NetControl::Rule`)


.. bro:id:: NetControl::broker_remove_rule

   :Type: :bro:type:`event` (id: :bro:type:`count`, r: :bro:type:`NetControl::Rule`, reason: :bro:type:`string`)


.. bro:id:: NetControl::broker_rule_added

   :Type: :bro:type:`event` (id: :bro:type:`count`, r: :bro:type:`NetControl::Rule`, msg: :bro:type:`string`)


.. bro:id:: NetControl::broker_rule_error

   :Type: :bro:type:`event` (id: :bro:type:`count`, r: :bro:type:`NetControl::Rule`, msg: :bro:type:`string`)


.. bro:id:: NetControl::broker_rule_exists

   :Type: :bro:type:`event` (id: :bro:type:`count`, r: :bro:type:`NetControl::Rule`, msg: :bro:type:`string`)


.. bro:id:: NetControl::broker_rule_removed

   :Type: :bro:type:`event` (id: :bro:type:`count`, r: :bro:type:`NetControl::Rule`, msg: :bro:type:`string`)


.. bro:id:: NetControl::broker_rule_timeout

   :Type: :bro:type:`event` (id: :bro:type:`count`, r: :bro:type:`NetControl::Rule`, i: :bro:type:`NetControl::FlowInfo`)


Functions
#########
.. bro:id:: NetControl::create_broker

   :Type: :bro:type:`function` (config: :bro:type:`NetControl::BrokerConfig`, can_expire: :bro:type:`bool`) : :bro:type:`NetControl::PluginState`

   Instantiates the broker plugin.


