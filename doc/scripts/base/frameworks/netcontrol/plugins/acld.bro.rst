:tocdepth: 3

base/frameworks/netcontrol/plugins/acld.bro
===========================================
.. bro:namespace:: NetControl

Acld plugin for the netcontrol framework.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/frameworks/netcontrol/main.bro </scripts/base/frameworks/netcontrol/main.bro>`, :doc:`base/frameworks/netcontrol/plugin.bro </scripts/base/frameworks/netcontrol/plugin.bro>`

Summary
~~~~~~~
Types
#####
====================================================== =
:bro:type:`NetControl::AclRule`: :bro:type:`record`    
:bro:type:`NetControl::AcldConfig`: :bro:type:`record` 
====================================================== =

Redefinitions
#############
======================================================= =
:bro:type:`NetControl::PluginState`: :bro:type:`record` 
======================================================= =

Events
######
========================================================== =======================================
:bro:id:`NetControl::acld_add_rule`: :bro:type:`event`     Events that are sent from us to Broker.
:bro:id:`NetControl::acld_remove_rule`: :bro:type:`event`  
:bro:id:`NetControl::acld_rule_added`: :bro:type:`event`   Events that are sent from Broker to us.
:bro:id:`NetControl::acld_rule_error`: :bro:type:`event`   
:bro:id:`NetControl::acld_rule_exists`: :bro:type:`event`  
:bro:id:`NetControl::acld_rule_removed`: :bro:type:`event` 
========================================================== =======================================

Hooks
#####
======================================================== ==============================================================
:bro:id:`NetControl::acld_rule_policy`: :bro:type:`hook` Hook that is called after a rule is converted to an acld rule.
======================================================== ==============================================================

Functions
#########
======================================================= =============================
:bro:id:`NetControl::create_acld`: :bro:type:`function` Instantiates the acld plugin.
======================================================= =============================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: NetControl::AclRule

   :Type: :bro:type:`record`

      command: :bro:type:`string`

      cookie: :bro:type:`count`

      arg: :bro:type:`string`

      comment: :bro:type:`string` :bro:attr:`&optional`


.. bro:type:: NetControl::AcldConfig

   :Type: :bro:type:`record`

      acld_topic: :bro:type:`string`
         The acld topic to send events to.

      acld_host: :bro:type:`addr`
         Broker host to connect to.

      acld_port: :bro:type:`port`
         Broker port to connect to.

      monitor: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Do we accept rules for the monitor path? Default false.

      forward: :bro:type:`bool` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         Do we accept rules for the forward path? Default true.

      check_pred: :bro:type:`function` (p: :bro:type:`NetControl::PluginState`, r: :bro:type:`NetControl::Rule`) : :bro:type:`bool` :bro:attr:`&optional`
         Predicate that is called on rule insertion or removal.
         

         :p: Current plugin state.
         

         :r: The rule to be inserted or removed.
         

         :returns: T if the rule can be handled by the current backend, F otherwise.


Events
######
.. bro:id:: NetControl::acld_add_rule

   :Type: :bro:type:`event` (id: :bro:type:`count`, r: :bro:type:`NetControl::Rule`, ar: :bro:type:`NetControl::AclRule`)

   Events that are sent from us to Broker.

.. bro:id:: NetControl::acld_remove_rule

   :Type: :bro:type:`event` (id: :bro:type:`count`, r: :bro:type:`NetControl::Rule`, ar: :bro:type:`NetControl::AclRule`)


.. bro:id:: NetControl::acld_rule_added

   :Type: :bro:type:`event` (id: :bro:type:`count`, r: :bro:type:`NetControl::Rule`, msg: :bro:type:`string`)

   Events that are sent from Broker to us.

.. bro:id:: NetControl::acld_rule_error

   :Type: :bro:type:`event` (id: :bro:type:`count`, r: :bro:type:`NetControl::Rule`, msg: :bro:type:`string`)


.. bro:id:: NetControl::acld_rule_exists

   :Type: :bro:type:`event` (id: :bro:type:`count`, r: :bro:type:`NetControl::Rule`, msg: :bro:type:`string`)


.. bro:id:: NetControl::acld_rule_removed

   :Type: :bro:type:`event` (id: :bro:type:`count`, r: :bro:type:`NetControl::Rule`, msg: :bro:type:`string`)


Hooks
#####
.. bro:id:: NetControl::acld_rule_policy

   :Type: :bro:type:`hook` (p: :bro:type:`NetControl::PluginState`, r: :bro:type:`NetControl::Rule`, ar: :bro:type:`NetControl::AclRule`) : :bro:type:`bool`

   Hook that is called after a rule is converted to an acld rule.
   The hook may modify the rule before it is sent to acld.
   Setting the acld command to F will cause the rule to be rejected
   by the plugin.
   

   :p: Current plugin state.
   

   :r: The rule to be inserted or removed.
   

   :ar: The acld rule to be inserted or removed.

Functions
#########
.. bro:id:: NetControl::create_acld

   :Type: :bro:type:`function` (config: :bro:type:`NetControl::AcldConfig`) : :bro:type:`NetControl::PluginState`

   Instantiates the acld plugin.


