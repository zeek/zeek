:tocdepth: 3

base/protocols/conn/removal-hooks.zeek
======================================
.. zeek:namespace:: Conn

Adds a framework for registering "connection removal hooks".
All registered hooks for a given connection get run within the
:zeek:see:`connection_state_remove` event for that connection.
This functionality is useful from a performance/scaling concern:
if every new protocol-analysis script uses
:zeek:see:`connection_state_remove` to implement its finalization/cleanup
logic, then all connections take the performance hit of dispatching that
event, even if they aren't related to that specific protocol.

:Namespace: Conn

Summary
~~~~~~~
Types
#####
================================================= ===========================================================================
:zeek:type:`Conn::RemovalHook`: :zeek:type:`hook` A hook function for use with either :zeek:see:`Conn::register_removal_hook`
                                                  or :zeek:see:`Conn::unregister_removal_hook`.
================================================= ===========================================================================

Redefinitions
#############
============================================ =========================================================================================
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               removal_hooks: :zeek:type:`set` [:zeek:type:`Conn::RemovalHook`] :zeek:attr:`&optional`
============================================ =========================================================================================

Functions
#########
=============================================================== =====================================================================
:zeek:id:`Conn::register_removal_hook`: :zeek:type:`function`   Register a hook that will later be called during a connection's
                                                                :zeek:see:`connection_state_remove` event.
:zeek:id:`Conn::unregister_removal_hook`: :zeek:type:`function` Unregister a hook that would have been called during a connection's
                                                                :zeek:see:`connection_state_remove` event such that it will no longer
                                                                be called.
=============================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Conn::RemovalHook
   :source-code: base/protocols/conn/removal-hooks.zeek 17 17

   :Type: :zeek:type:`hook` (c: :zeek:type:`connection`) : :zeek:type:`bool`

   A hook function for use with either :zeek:see:`Conn::register_removal_hook`
   or :zeek:see:`Conn::unregister_removal_hook`.  The :zeek:see:`connection`
   argument refers to the connection currently being removed within a
   :zeek:see:`connection_state_remove` event.

Functions
#########
.. zeek:id:: Conn::register_removal_hook
   :source-code: base/protocols/conn/removal-hooks.zeek 47 60

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, hk: :zeek:type:`Conn::RemovalHook`) : :zeek:type:`bool`

   Register a hook that will later be called during a connection's
   :zeek:see:`connection_state_remove` event.
   

   :param c: The associated connection whose :zeek:see:`connection_state_remove`
      event should trigger a callback to *hk*.
   

   :param hk: The hook function to use as a callback.
   

   :returns: false if the provided hook was previously registered, else true.

.. zeek:id:: Conn::unregister_removal_hook
   :source-code: base/protocols/conn/removal-hooks.zeek 62 72

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, hk: :zeek:type:`Conn::RemovalHook`) : :zeek:type:`bool`

   Unregister a hook that would have been called during a connection's
   :zeek:see:`connection_state_remove` event such that it will no longer
   be called.
   

   :param c: The associated connection whose :zeek:see:`connection_state_remove`
      event could have triggered a callback to *hk*.
   

   :param hk: The hook function that would have been used as a callback.
   

   :returns: true if the provided hook was previously registered, else false.


