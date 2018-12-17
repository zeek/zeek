:tocdepth: 3

base/frameworks/netcontrol/types.bro
====================================
.. bro:namespace:: NetControl

This file defines the types that are used by the NetControl framework.

The most important type defined in this file is :bro:see:`NetControl::Rule`,
which is used to describe all rules that can be expressed by the NetControl framework. 

:Namespace: NetControl

Summary
~~~~~~~
Runtime Options
###############
========================================================================== ======================================================
:bro:id:`NetControl::default_priority`: :bro:type:`int` :bro:attr:`&redef` The default priority that is used when creating rules.
========================================================================== ======================================================

Redefinable Options
###################
============================================================================ ====================================================================================
:bro:id:`NetControl::whitelist_priority`: :bro:type:`int` :bro:attr:`&redef` The default priority that is used when using the high-level functions to
                                                                             push whitelist entries to the backends (:bro:see:`NetControl::whitelist_address` and
                                                                             :bro:see:`NetControl::whitelist_subnet`).
============================================================================ ====================================================================================

Types
#####
==================================================== ====================================================================================================
:bro:type:`NetControl::Entity`: :bro:type:`record`   Type defining the entity a rule is operating on.
:bro:type:`NetControl::EntityType`: :bro:type:`enum` Type defining the entity that a rule applies to.
:bro:type:`NetControl::Flow`: :bro:type:`record`     Flow is used in :bro:type:`NetControl::Entity` together with :bro:enum:`NetControl::FLOW` to specify
                                                     a uni-directional flow that a rule applies to.
:bro:type:`NetControl::FlowInfo`: :bro:type:`record` Information of a flow that can be provided by switches when the flow times out.
:bro:type:`NetControl::FlowMod`: :bro:type:`record`  Type for defining a flow modification action.
:bro:type:`NetControl::Rule`: :bro:type:`record`     A rule for the framework to put in place.
:bro:type:`NetControl::RuleType`: :bro:type:`enum`   Type of rules that the framework supports.
:bro:type:`NetControl::TargetType`: :bro:type:`enum` Type defining the target of a rule.
==================================================== ====================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: NetControl::default_priority

   :Type: :bro:type:`int`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0``

   The default priority that is used when creating rules.

Redefinable Options
###################
.. bro:id:: NetControl::whitelist_priority

   :Type: :bro:type:`int`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5``

   The default priority that is used when using the high-level functions to
   push whitelist entries to the backends (:bro:see:`NetControl::whitelist_address` and
   :bro:see:`NetControl::whitelist_subnet`).
   
   Note that this priority is not automatically used when manually creating rules
   that have a :bro:see:`NetControl::RuleType` of :bro:enum:`NetControl::WHITELIST`.

Types
#####
.. bro:type:: NetControl::Entity

   :Type: :bro:type:`record`

      ty: :bro:type:`NetControl::EntityType`
         Type of entity.

      conn: :bro:type:`conn_id` :bro:attr:`&optional`
         Used with :bro:enum:`NetControl::CONNECTION`.

      flow: :bro:type:`NetControl::Flow` :bro:attr:`&optional`
         Used with :bro:enum:`NetControl::FLOW`.

      ip: :bro:type:`subnet` :bro:attr:`&optional`
         Used with :bro:enum:`NetControl::ADDRESS` to specifiy a CIDR subnet.

      mac: :bro:type:`string` :bro:attr:`&optional`
         Used with :bro:enum:`NetControl::MAC`.

   Type defining the entity a rule is operating on.

.. bro:type:: NetControl::EntityType

   :Type: :bro:type:`enum`

      .. bro:enum:: NetControl::ADDRESS NetControl::EntityType

         Activity involving a specific IP address.

      .. bro:enum:: NetControl::CONNECTION NetControl::EntityType

         Activity involving all of a bi-directional connection's activity.

      .. bro:enum:: NetControl::FLOW NetControl::EntityType

         Activity involving a uni-directional flow's activity. Can contain wildcards.

      .. bro:enum:: NetControl::MAC NetControl::EntityType

         Activity involving a MAC address.

   Type defining the entity that a rule applies to.

.. bro:type:: NetControl::Flow

   :Type: :bro:type:`record`

      src_h: :bro:type:`subnet` :bro:attr:`&optional`
         The source IP address/subnet.

      src_p: :bro:type:`port` :bro:attr:`&optional`
         The source port number.

      dst_h: :bro:type:`subnet` :bro:attr:`&optional`
         The destination IP address/subnet.

      dst_p: :bro:type:`port` :bro:attr:`&optional`
         The destination port number.

      src_m: :bro:type:`string` :bro:attr:`&optional`
         The source MAC address.

      dst_m: :bro:type:`string` :bro:attr:`&optional`
         The destination MAC address.

   Flow is used in :bro:type:`NetControl::Entity` together with :bro:enum:`NetControl::FLOW` to specify
   a uni-directional flow that a rule applies to.
   
   If optional fields are not set, they are interpreted as wildcarded.

.. bro:type:: NetControl::FlowInfo

   :Type: :bro:type:`record`

      duration: :bro:type:`interval` :bro:attr:`&optional`
         Total duration of the rule.

      packet_count: :bro:type:`count` :bro:attr:`&optional`
         Number of packets exchanged over connections matched by the rule.

      byte_count: :bro:type:`count` :bro:attr:`&optional`
         Total bytes exchanged over connections matched by the rule.

   Information of a flow that can be provided by switches when the flow times out.
   Currently this is heavily influenced by the data that OpenFlow returns by default.
   That being said - their design makes sense and this is probably the data one
   can expect to be available.

.. bro:type:: NetControl::FlowMod

   :Type: :bro:type:`record`

      src_h: :bro:type:`addr` :bro:attr:`&optional`
         The source IP address.

      src_p: :bro:type:`count` :bro:attr:`&optional`
         The source port number.

      dst_h: :bro:type:`addr` :bro:attr:`&optional`
         The destination IP address.

      dst_p: :bro:type:`count` :bro:attr:`&optional`
         The destination port number.

      src_m: :bro:type:`string` :bro:attr:`&optional`
         The source MAC address.

      dst_m: :bro:type:`string` :bro:attr:`&optional`
         The destination MAC address.

      redirect_port: :bro:type:`count` :bro:attr:`&optional`

   Type for defining a flow modification action.

.. bro:type:: NetControl::Rule

   :Type: :bro:type:`record`

      ty: :bro:type:`NetControl::RuleType`
         Type of rule.

      target: :bro:type:`NetControl::TargetType`
         Where to apply rule.

      entity: :bro:type:`NetControl::Entity`
         Entity to apply rule to.

      expire: :bro:type:`interval` :bro:attr:`&optional`
         Timeout after which to expire the rule.

      priority: :bro:type:`int` :bro:attr:`&default` = :bro:see:`NetControl::default_priority` :bro:attr:`&optional`
         Priority if multiple rules match an entity (larger value is higher priority).

      location: :bro:type:`string` :bro:attr:`&optional`
         Optional string describing where/what installed the rule.

      out_port: :bro:type:`count` :bro:attr:`&optional`
         Argument for :bro:enum:`NetControl::REDIRECT` rules.

      mod: :bro:type:`NetControl::FlowMod` :bro:attr:`&optional`
         Argument for :bro:enum:`NetControl::MODIFY` rules.

      id: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`
         Internally determined unique ID for this rule. Will be set when added.

      cid: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Internally determined unique numeric ID for this rule. Set when added.

      _plugin_ids: :bro:type:`set` [:bro:type:`count`] :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/main.bro` is loaded)

         Internally set to the plugins handling the rule.

      _active_plugin_ids: :bro:type:`set` [:bro:type:`count`] :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/main.bro` is loaded)

         Internally set to the plugins on which the rule is currently active.

      _no_expire_plugins: :bro:type:`set` [:bro:type:`count`] :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/main.bro` is loaded)

         Internally set to plugins where the rule should not be removed upon timeout.

      _added: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/main.bro` is loaded)

         Track if the rule was added successfully by all responsible plugins.

   A rule for the framework to put in place. Of all rules currently in
   place, the first match will be taken, sorted by priority. All
   further rules will be ignored.

.. bro:type:: NetControl::RuleType

   :Type: :bro:type:`enum`

      .. bro:enum:: NetControl::DROP NetControl::RuleType

         Stop forwarding all packets matching the entity.
         
         No additional arguments.

      .. bro:enum:: NetControl::MODIFY NetControl::RuleType

         Modify all packets matching entity. The packets
         will be modified according to the `mod` entry of
         the rule.
         

      .. bro:enum:: NetControl::REDIRECT NetControl::RuleType

         Redirect all packets matching entity to a different switch port,
         given in the `out_port` argument of the rule.
         

      .. bro:enum:: NetControl::WHITELIST NetControl::RuleType

         Whitelists all packets of an entity, meaning no restrictions will be applied.
         While whitelisting is the default if no rule matches, this type can be
         used to override lower-priority rules that would otherwise take effect for the
         entity.

   Type of rules that the framework supports. Each type lists the extra
   :bro:type:`NetControl::Rule` fields it uses, if any.
   
   Plugins may extend this type to define their own.

.. bro:type:: NetControl::TargetType

   :Type: :bro:type:`enum`

      .. bro:enum:: NetControl::FORWARD NetControl::TargetType

      .. bro:enum:: NetControl::MONITOR NetControl::TargetType

   Type defining the target of a rule.
   
   Rules can either be applied to the forward path, affecting all network traffic, or
   on the monitor path, only affecting the traffic that is sent to Bro. The second
   is mostly used for shunting, which allows Bro to tell the networking hardware that
   it wants to no longer see traffic that it identified as benign.


