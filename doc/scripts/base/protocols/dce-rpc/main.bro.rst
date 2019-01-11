:tocdepth: 3

base/protocols/dce-rpc/main.bro
===============================
.. bro:namespace:: DCE_RPC


:Namespace: DCE_RPC
:Imports: :doc:`base/frameworks/dpd </scripts/base/frameworks/dpd/index>`, :doc:`base/protocols/dce-rpc/consts.bro </scripts/base/protocols/dce-rpc/consts.bro>`

Summary
~~~~~~~
Runtime Options
###############
=========================================================================== ===============================================================
:bro:id:`DCE_RPC::ignored_operations`: :bro:type:`table` :bro:attr:`&redef` These are DCE-RPC operations that are ignored, typically due to
                                                                            the operations being noisy and low value on most networks.
=========================================================================== ===============================================================

Types
#####
===================================================== =
:bro:type:`DCE_RPC::BackingState`: :bro:type:`record` 
:bro:type:`DCE_RPC::Info`: :bro:type:`record`         
:bro:type:`DCE_RPC::State`: :bro:type:`record`        
===================================================== =

Redefinitions
#############
==================================================================== =
:bro:id:`DPD::ignore_violations`: :bro:type:`set` :bro:attr:`&redef` 
:bro:type:`Log::ID`: :bro:type:`enum`                                
:bro:type:`connection`: :bro:type:`record`                           
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef`    
==================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: DCE_RPC::ignored_operations

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
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
.. bro:type:: DCE_RPC::BackingState

   :Type: :bro:type:`record`

      info: :bro:type:`DCE_RPC::Info`

      state: :bro:type:`DCE_RPC::State`


.. bro:type:: DCE_RPC::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp for when the event happened.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      rtt: :bro:type:`interval` :bro:attr:`&log` :bro:attr:`&optional`
         Round trip time from the request to the response.
         If either the request or response wasn't seen, 
         this will be null.

      named_pipe: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Remote pipe name.

      endpoint: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Endpoint name looked up from the uuid.

      operation: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Operation seen in the call.


.. bro:type:: DCE_RPC::State

   :Type: :bro:type:`record`

      uuid: :bro:type:`string` :bro:attr:`&optional`

      named_pipe: :bro:type:`string` :bro:attr:`&optional`

      ctx_to_uuid: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string` :bro:attr:`&optional`



