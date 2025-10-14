:tocdepth: 3

base/frameworks/netcontrol/plugins/acld.zeek
============================================
.. zeek:namespace:: NetControl

Acld plugin for the netcontrol framework.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/frameworks/netcontrol/main.zeek </scripts/base/frameworks/netcontrol/main.zeek>`, :doc:`base/frameworks/netcontrol/plugin.zeek </scripts/base/frameworks/netcontrol/plugin.zeek>`

Summary
~~~~~~~
Types
#####
======================================================== =
:zeek:type:`NetControl::AclRule`: :zeek:type:`record`    
:zeek:type:`NetControl::AcldConfig`: :zeek:type:`record` 
======================================================== =

Redefinitions
#############
========================================================= =========================================================================
:zeek:type:`NetControl::PluginState`: :zeek:type:`record` 
                                                          
                                                          :New Fields: :zeek:type:`NetControl::PluginState`
                                                          
                                                            acld_config: :zeek:type:`NetControl::AcldConfig` :zeek:attr:`&optional`
                                                          
                                                            acld_id: :zeek:type:`count` :zeek:attr:`&optional`
                                                              The ID of this acld instance - for the mapping to PluginStates.
========================================================= =========================================================================

Events
######
============================================================ =======================================
:zeek:id:`NetControl::acld_add_rule`: :zeek:type:`event`     Events that are sent from us to Broker.
:zeek:id:`NetControl::acld_remove_rule`: :zeek:type:`event`  
:zeek:id:`NetControl::acld_rule_added`: :zeek:type:`event`   Events that are sent from Broker to us.
:zeek:id:`NetControl::acld_rule_error`: :zeek:type:`event`   
:zeek:id:`NetControl::acld_rule_exists`: :zeek:type:`event`  
:zeek:id:`NetControl::acld_rule_removed`: :zeek:type:`event` 
============================================================ =======================================

Hooks
#####
========================================================== ==============================================================
:zeek:id:`NetControl::acld_rule_policy`: :zeek:type:`hook` Hook that is called after a rule is converted to an acld rule.
========================================================== ==============================================================

Functions
#########
========================================================= =============================
:zeek:id:`NetControl::create_acld`: :zeek:type:`function` Instantiates the acld plugin.
========================================================= =============================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: NetControl::AclRule
   :source-code: base/frameworks/netcontrol/plugins/acld.zeek 10 15

   :Type: :zeek:type:`record`

      command: :zeek:type:`string`

      cookie: :zeek:type:`count`

      arg: :zeek:type:`string`

      comment: :zeek:type:`string` :zeek:attr:`&optional`


.. zeek:type:: NetControl::AcldConfig
   :source-code: base/frameworks/netcontrol/plugins/acld.zeek 17 37

   :Type: :zeek:type:`record`

      acld_topic: :zeek:type:`string`
         The acld topic to send events to.

      acld_host: :zeek:type:`addr`
         Broker host to connect to.

      acld_port: :zeek:type:`port`
         Broker port to connect to.

      monitor: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Do we accept rules for the monitor path? Default false.

      forward: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         Do we accept rules for the forward path? Default true.

      check_pred: :zeek:type:`function` (p: :zeek:type:`NetControl::PluginState`, r: :zeek:type:`NetControl::Rule`) : :zeek:type:`bool` :zeek:attr:`&optional`
         Predicate that is called on rule insertion or removal.
         

         :param p: Current plugin state.
         

         :param r: The rule to be inserted or removed.
         

         :returns: T if the rule can be handled by the current backend, F otherwise.


Events
######
.. zeek:id:: NetControl::acld_add_rule
   :source-code: base/frameworks/netcontrol/plugins/acld.zeek 61 61

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, ar: :zeek:type:`NetControl::AclRule`)

   Events that are sent from us to Broker.

.. zeek:id:: NetControl::acld_remove_rule
   :source-code: base/frameworks/netcontrol/plugins/acld.zeek 62 62

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, ar: :zeek:type:`NetControl::AclRule`)


.. zeek:id:: NetControl::acld_rule_added
   :source-code: base/frameworks/netcontrol/plugins/acld.zeek 90 101

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, msg: :zeek:type:`string`)

   Events that are sent from Broker to us.

.. zeek:id:: NetControl::acld_rule_error
   :source-code: base/frameworks/netcontrol/plugins/acld.zeek 129 140

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, msg: :zeek:type:`string`)


.. zeek:id:: NetControl::acld_rule_exists
   :source-code: base/frameworks/netcontrol/plugins/acld.zeek 103 114

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, msg: :zeek:type:`string`)


.. zeek:id:: NetControl::acld_rule_removed
   :source-code: base/frameworks/netcontrol/plugins/acld.zeek 116 127

   :Type: :zeek:type:`event` (id: :zeek:type:`count`, r: :zeek:type:`NetControl::Rule`, msg: :zeek:type:`string`)


Hooks
#####
.. zeek:id:: NetControl::acld_rule_policy
   :source-code: base/frameworks/netcontrol/plugins/acld.zeek 58 58

   :Type: :zeek:type:`hook` (p: :zeek:type:`NetControl::PluginState`, r: :zeek:type:`NetControl::Rule`, ar: :zeek:type:`NetControl::AclRule`) : :zeek:type:`bool`

   Hook that is called after a rule is converted to an acld rule.
   The hook may modify the rule before it is sent to acld.
   Setting the acld command to F will cause the rule to be rejected
   by the plugin.
   

   :param p: Current plugin state.
   

   :param r: The rule to be inserted or removed.
   

   :param ar: The acld rule to be inserted or removed.

Functions
#########
.. zeek:id:: NetControl::create_acld
   :source-code: base/frameworks/netcontrol/plugins/acld.zeek 298 317

   :Type: :zeek:type:`function` (config: :zeek:type:`NetControl::AcldConfig`) : :zeek:type:`NetControl::PluginState`

   Instantiates the acld plugin.


