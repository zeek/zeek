:tocdepth: 3

base/protocols/dce-rpc/main.zeek
================================
.. zeek:namespace:: DCE_RPC


:Namespace: DCE_RPC
:Imports: :doc:`base/frameworks/dpd </scripts/base/frameworks/dpd/index>`, :doc:`base/protocols/dce-rpc/consts.zeek </scripts/base/protocols/dce-rpc/consts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================== ===============================================================
:zeek:id:`DCE_RPC::ignored_operations`: :zeek:type:`table` :zeek:attr:`&redef` These are DCE-RPC operations that are ignored, typically due to
                                                                               the operations being noisy and low value on most networks.
============================================================================== ===============================================================

Types
#####
======================================================= =
:zeek:type:`DCE_RPC::BackingState`: :zeek:type:`record` 
:zeek:type:`DCE_RPC::Info`: :zeek:type:`record`         
:zeek:type:`DCE_RPC::State`: :zeek:type:`record`        
======================================================= =

Redefinitions
#############
======================================================================= =
:zeek:id:`DPD::ignore_violations`: :zeek:type:`set` :zeek:attr:`&redef` 
:zeek:type:`Log::ID`: :zeek:type:`enum`                                 
:zeek:type:`connection`: :zeek:type:`record`                            
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef`    
======================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: DCE_RPC::ignored_operations

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            ["winreg"] = {
               "BaseRegOpenKey",
               "BaseRegEnumKey",
               "OpenClassesRoot",
               "BaseRegCloseKey",
               "OpenLocalMachine",
               "BaseRegQueryValue",
               "BaseRegDeleteKeyEx",
               "BaseRegGetVersion"
            },
            ["spoolss"] = {
               "RpcSplOpenPrinter",
               "RpcClosePrinter"
            },
            ["wkssvc"] = {
               "NetrWkstaGetInfo"
            }
         }


   These are DCE-RPC operations that are ignored, typically due to
   the operations being noisy and low value on most networks.

Types
#####
.. zeek:type:: DCE_RPC::BackingState

   :Type: :zeek:type:`record`

      info: :zeek:type:`DCE_RPC::Info`

      state: :zeek:type:`DCE_RPC::State`


.. zeek:type:: DCE_RPC::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp for when the event happened.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      rtt: :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&optional`
         Round trip time from the request to the response.
         If either the request or response wasn't seen, 
         this will be null.

      named_pipe: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Remote pipe name.

      endpoint: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Endpoint name looked up from the uuid.

      operation: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Operation seen in the call.


.. zeek:type:: DCE_RPC::State

   :Type: :zeek:type:`record`

      uuid: :zeek:type:`string` :zeek:attr:`&optional`

      named_pipe: :zeek:type:`string` :zeek:attr:`&optional`

      ctx_to_uuid: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string` :zeek:attr:`&optional`



