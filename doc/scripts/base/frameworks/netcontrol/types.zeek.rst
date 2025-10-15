:tocdepth: 3

base/frameworks/netcontrol/types.zeek
=====================================
.. zeek:namespace:: NetControl

This file defines the types that are used by the NetControl framework.

The most important type defined in this file is :zeek:see:`NetControl::Rule`,
which is used to describe all rules that can be expressed by the NetControl framework.

:Namespace: NetControl

Summary
~~~~~~~
Runtime Options
###############
============================================================================= ======================================================
:zeek:id:`NetControl::default_priority`: :zeek:type:`int` :zeek:attr:`&redef` The default priority that is used when creating rules.
============================================================================= ======================================================

Redefinable Options
###################
=============================================================================== =====================================================================================
:zeek:id:`NetControl::whitelist_priority`: :zeek:type:`int` :zeek:attr:`&redef` The default priority that is used when using the high-level functions to
                                                                                push whitelist entries to the backends (:zeek:see:`NetControl::whitelist_address` and
                                                                                :zeek:see:`NetControl::whitelist_subnet`).
=============================================================================== =====================================================================================

Types
#####
====================================================== ======================================================================================================
:zeek:type:`NetControl::Entity`: :zeek:type:`record`   Type defining the entity a rule is operating on.
:zeek:type:`NetControl::EntityType`: :zeek:type:`enum` Type defining the entity that a rule applies to.
:zeek:type:`NetControl::Flow`: :zeek:type:`record`     Flow is used in :zeek:type:`NetControl::Entity` together with :zeek:enum:`NetControl::FLOW` to specify
                                                       a uni-directional flow that a rule applies to.
:zeek:type:`NetControl::FlowInfo`: :zeek:type:`record` Information of a flow that can be provided by switches when the flow times out.
:zeek:type:`NetControl::FlowMod`: :zeek:type:`record`  Type for defining a flow modification action.
:zeek:type:`NetControl::Rule`: :zeek:type:`record`     A rule for the framework to put in place.
:zeek:type:`NetControl::RuleType`: :zeek:type:`enum`   Type of rules that the framework supports.
:zeek:type:`NetControl::TargetType`: :zeek:type:`enum` Type defining the target of a rule.
====================================================== ======================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: NetControl::default_priority
   :source-code: base/frameworks/netcontrol/types.zeek 10 10

   :Type: :zeek:type:`int`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``

   The default priority that is used when creating rules.

Redefinable Options
###################
.. zeek:id:: NetControl::whitelist_priority
   :source-code: base/frameworks/netcontrol/types.zeek 18 18

   :Type: :zeek:type:`int`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5``

   The default priority that is used when using the high-level functions to
   push whitelist entries to the backends (:zeek:see:`NetControl::whitelist_address` and
   :zeek:see:`NetControl::whitelist_subnet`).
   
   Note that this priority is not automatically used when manually creating rules
   that have a :zeek:see:`NetControl::RuleType` of :zeek:enum:`NetControl::WHITELIST`.

Types
#####
.. zeek:type:: NetControl::Entity
   :source-code: base/frameworks/netcontrol/types.zeek 42 48

   :Type: :zeek:type:`record`

      ty: :zeek:type:`NetControl::EntityType`
         Type of entity.

      conn: :zeek:type:`conn_id` :zeek:attr:`&optional`
         Used with :zeek:enum:`NetControl::CONNECTION`.

      flow: :zeek:type:`NetControl::Flow` :zeek:attr:`&optional`
         Used with :zeek:enum:`NetControl::FLOW`.

      ip: :zeek:type:`subnet` :zeek:attr:`&optional`
         Used with :zeek:enum:`NetControl::ADDRESS` to specify a CIDR subnet.

      mac: :zeek:type:`string` :zeek:attr:`&optional`
         Used with :zeek:enum:`NetControl::MAC`.

   Type defining the entity a rule is operating on.

.. zeek:type:: NetControl::EntityType
   :source-code: base/frameworks/netcontrol/types.zeek 21 27

   :Type: :zeek:type:`enum`

      .. zeek:enum:: NetControl::ADDRESS NetControl::EntityType

         Activity involving a specific IP address.

      .. zeek:enum:: NetControl::CONNECTION NetControl::EntityType

         Activity involving all of a bi-directional connection's activity.

      .. zeek:enum:: NetControl::FLOW NetControl::EntityType

         Activity involving a uni-directional flow's activity. Can contain wildcards.

      .. zeek:enum:: NetControl::MAC NetControl::EntityType

         Activity involving a MAC address.

   Type defining the entity that a rule applies to.

.. zeek:type:: NetControl::Flow
   :source-code: base/frameworks/netcontrol/types.zeek 32 39

   :Type: :zeek:type:`record`

      src_h: :zeek:type:`subnet` :zeek:attr:`&optional`
         The source IP address/subnet.

      src_p: :zeek:type:`port` :zeek:attr:`&optional`
         The source port number.

      dst_h: :zeek:type:`subnet` :zeek:attr:`&optional`
         The destination IP address/subnet.

      dst_p: :zeek:type:`port` :zeek:attr:`&optional`
         The destination port number.

      src_m: :zeek:type:`string` :zeek:attr:`&optional`
         The source MAC address.

      dst_m: :zeek:type:`string` :zeek:attr:`&optional`
         The destination MAC address.

   Flow is used in :zeek:type:`NetControl::Entity` together with :zeek:enum:`NetControl::FLOW` to specify
   a uni-directional flow that a rule applies to.
   
   If optional fields are not set, they are interpreted as wildcarded.

.. zeek:type:: NetControl::FlowInfo
   :source-code: base/frameworks/netcontrol/types.zeek 122 126

   :Type: :zeek:type:`record`

      duration: :zeek:type:`interval` :zeek:attr:`&optional`
         Total duration of the rule.

      packet_count: :zeek:type:`count` :zeek:attr:`&optional`
         Number of packets exchanged over connections matched by the rule.

      byte_count: :zeek:type:`count` :zeek:attr:`&optional`
         Total bytes exchanged over connections matched by the rule.

   Information of a flow that can be provided by switches when the flow times out.
   Currently this is heavily influenced by the data that OpenFlow returns by default.
   That being said - their design makes sense and this is probably the data one
   can expect to be available.

.. zeek:type:: NetControl::FlowMod
   :source-code: base/frameworks/netcontrol/types.zeek 90 98

   :Type: :zeek:type:`record`

      src_h: :zeek:type:`addr` :zeek:attr:`&optional`
         The source IP address.

      src_p: :zeek:type:`count` :zeek:attr:`&optional`
         The source port number.

      dst_h: :zeek:type:`addr` :zeek:attr:`&optional`
         The destination IP address.

      dst_p: :zeek:type:`count` :zeek:attr:`&optional`
         The destination port number.

      src_m: :zeek:type:`string` :zeek:attr:`&optional`
         The source MAC address.

      dst_m: :zeek:type:`string` :zeek:attr:`&optional`
         The destination MAC address.

      redirect_port: :zeek:type:`count` :zeek:attr:`&optional`

   Type for defining a flow modification action.

.. zeek:type:: NetControl::Rule
   :source-code: base/frameworks/netcontrol/types.zeek 103 116

   :Type: :zeek:type:`record`

      ty: :zeek:type:`NetControl::RuleType`
         Type of rule.

      target: :zeek:type:`NetControl::TargetType`
         Where to apply rule.

      entity: :zeek:type:`NetControl::Entity`
         Entity to apply rule to.

      expire: :zeek:type:`interval` :zeek:attr:`&optional`
         Timeout after which to expire the rule.

      priority: :zeek:type:`int` :zeek:attr:`&default` = :zeek:see:`NetControl::default_priority` :zeek:attr:`&optional`
         Priority if multiple rules match an entity (larger value is higher priority).

      location: :zeek:type:`string` :zeek:attr:`&optional`
         Optional string describing where/what installed the rule.

      out_port: :zeek:type:`count` :zeek:attr:`&optional`
         Argument for :zeek:enum:`NetControl::REDIRECT` rules.

      mod: :zeek:type:`NetControl::FlowMod` :zeek:attr:`&optional`
         Argument for :zeek:enum:`NetControl::MODIFY` rules.

      id: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         Internally determined unique ID for this rule. Will be set when added.

      cid: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Internally determined unique numeric ID for this rule. Set when added.

      _plugin_ids: :zeek:type:`set` [:zeek:type:`count`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/main.zeek` is loaded)

         Internally set to the plugins handling the rule.

      _active_plugin_ids: :zeek:type:`set` [:zeek:type:`count`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/main.zeek` is loaded)

         Internally set to the plugins on which the rule is currently active.

      _no_expire_plugins: :zeek:type:`set` [:zeek:type:`count`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/main.zeek` is loaded)

         Internally set to plugins where the rule should not be removed upon timeout.

      _added: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/netcontrol/main.zeek` is loaded)

         Track if the rule was added successfully by all responsible plugins.

   A rule for the framework to put in place. Of all rules currently in
   place, the first match will be taken, sorted by priority. All
   further rules will be ignored.

.. zeek:type:: NetControl::RuleType
   :source-code: base/frameworks/netcontrol/types.zeek 65 88

   :Type: :zeek:type:`enum`

      .. zeek:enum:: NetControl::DROP NetControl::RuleType

         Stop forwarding all packets matching the entity.
         
         No additional arguments.

      .. zeek:enum:: NetControl::MODIFY NetControl::RuleType

         Modify all packets matching entity. The packets
         will be modified according to the `mod` entry of
         the rule.
         

      .. zeek:enum:: NetControl::REDIRECT NetControl::RuleType

         Redirect all packets matching entity to a different switch port,
         given in the `out_port` argument of the rule.
         

      .. zeek:enum:: NetControl::WHITELIST NetControl::RuleType

         Whitelists all packets of an entity, meaning no restrictions will be applied.
         While whitelisting is the default if no rule matches, this type can be
         used to override lower-priority rules that would otherwise take effect for the
         entity.

   Type of rules that the framework supports. Each type lists the extra
   :zeek:type:`NetControl::Rule` fields it uses, if any.
   
   Plugins may extend this type to define their own.

.. zeek:type:: NetControl::TargetType
   :source-code: base/frameworks/netcontrol/types.zeek 56 60

   :Type: :zeek:type:`enum`

      .. zeek:enum:: NetControl::FORWARD NetControl::TargetType

      .. zeek:enum:: NetControl::MONITOR NetControl::TargetType

   Type defining the target of a rule.
   
   Rules can either be applied to the forward path, affecting all network traffic, or
   on the monitor path, only affecting the traffic that is sent to Zeek. The second
   is mostly used for shunting, which allows Zeek to tell the networking hardware that
   it wants to no longer see traffic that it identified as benign.


