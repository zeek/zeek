:tocdepth: 3

base/protocols/dce-rpc/main.zeek
================================
.. zeek:namespace:: DCE_RPC


:Namespace: DCE_RPC
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/dce-rpc/consts.zeek </scripts/base/protocols/dce-rpc/consts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================== ===============================================================
:zeek:id:`DCE_RPC::ignored_operations`: :zeek:type:`table` :zeek:attr:`&redef` These are DCE-RPC operations that are ignored, typically due to
                                                                               the operations being noisy and low value on most networks.
============================================================================== ===============================================================

Redefinable Options
###################
=============================================================== =============================
:zeek:id:`DCE_RPC::ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for DCE/RPC.
=============================================================== =============================

Types
#####
======================================================= =
:zeek:type:`DCE_RPC::BackingState`: :zeek:type:`record`
:zeek:type:`DCE_RPC::Info`: :zeek:type:`record`
:zeek:type:`DCE_RPC::State`: :zeek:type:`record`
======================================================= =

Redefinitions
#############
======================================================================= =======================================================================================================================
:zeek:id:`DPD::ignore_violations`: :zeek:type:`set` :zeek:attr:`&redef`
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                                                        * :zeek:enum:`DCE_RPC::LOG`
:zeek:type:`connection`: :zeek:type:`record`

                                                                        :New Fields: :zeek:type:`connection`

                                                                          dce_rpc: :zeek:type:`DCE_RPC::Info` :zeek:attr:`&optional`

                                                                          dce_rpc_state: :zeek:type:`DCE_RPC::State` :zeek:attr:`&optional`

                                                                          dce_rpc_backing: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`DCE_RPC::BackingState` :zeek:attr:`&optional`
======================================================================= =======================================================================================================================

Hooks
#####
==================================================================== ==========================
:zeek:id:`DCE_RPC::finalize_dce_rpc`: :zeek:type:`Conn::RemovalHook` DCE_RPC finalization hook.
:zeek:id:`DCE_RPC::log_policy`: :zeek:type:`Log::PolicyHook`
==================================================================== ==========================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: DCE_RPC::ignored_operations
   :source-code: base/protocols/dce-rpc/main.zeek 48 48

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            ["spoolss"] = {
               "RpcSplOpenPrinter",
               "RpcClosePrinter"
            },
            ["wkssvc"] = {
               "NetrWkstaGetInfo"
            },
            ["winreg"] = {
               "BaseRegCloseKey",
               "BaseRegGetVersion",
               "BaseRegOpenKey",
               "BaseRegDeleteKeyEx",
               "BaseRegEnumKey",
               "OpenLocalMachine",
               "BaseRegQueryValue",
               "OpenClassesRoot"
            }
         }


   These are DCE-RPC operations that are ignored, typically due to
   the operations being noisy and low value on most networks.

Redefinable Options
###################
.. zeek:id:: DCE_RPC::ports
   :source-code: base/protocols/dce-rpc/main.zeek 10 10

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            135/tcp
         }


   Well-known ports for DCE/RPC.

Types
#####
.. zeek:type:: DCE_RPC::BackingState
   :source-code: base/protocols/dce-rpc/main.zeek 62 65

   :Type: :zeek:type:`record`


   .. zeek:field:: info :zeek:type:`DCE_RPC::Info`


   .. zeek:field:: state :zeek:type:`DCE_RPC::State`



.. zeek:type:: DCE_RPC::Info
   :source-code: base/protocols/dce-rpc/main.zeek 14 44

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the event happened.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: rtt :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&optional`

      Round trip time from the request to the response.
      If either the request or response wasn't seen,
      this will be null.


   .. zeek:field:: named_pipe :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Remote pipe name.

      Note that this value is from the "sec_addr" field in the
      protocol. Zeek uses the "named_pipe" name for historical reasons,
      but it may also contain local port numbers rather than named pipes.

      If you prefer to use the "secondary address" name, consider
      using :zeek:see:`Log::default_field_name_map`, a ``Log::Filter``'s
      :zeek:field:`Log::Filter$field_name_map` field, or removing
      the :zeek:attr:`&log` attribute from this field, adding a
      new :zeek:field:`sec_addr` field and populating it in a custom
      :zeek:see:`dce_rpc_bind_ack` event handler based on the
      :zeek:field:`named_pipe` value.


   .. zeek:field:: endpoint :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Endpoint name looked up from the uuid.


   .. zeek:field:: operation :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Operation seen in the call.



.. zeek:type:: DCE_RPC::State
   :source-code: base/protocols/dce-rpc/main.zeek 54 58

   :Type: :zeek:type:`record`


   .. zeek:field:: uuid :zeek:type:`string` :zeek:attr:`&optional`


   .. zeek:field:: named_pipe :zeek:type:`string` :zeek:attr:`&optional`


   .. zeek:field:: ctx_to_uuid :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string` :zeek:attr:`&optional`



Hooks
#####
.. zeek:id:: DCE_RPC::finalize_dce_rpc
   :source-code: base/protocols/dce-rpc/main.zeek 248 280

   :Type: :zeek:type:`Conn::RemovalHook`

   DCE_RPC finalization hook.  Remaining DCE_RPC info may get logged when it's called.

.. zeek:id:: DCE_RPC::log_policy
   :source-code: base/protocols/dce-rpc/main.zeek 12 12

   :Type: :zeek:type:`Log::PolicyHook`



