:tocdepth: 3

base/bif/plugins/Bro_DCE_RPC.events.bif.zeek
============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================= ==============================================================================================================================
:zeek:id:`dce_rpc_alter_context`: :zeek:type:`event`      Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` alter context request message.
:zeek:id:`dce_rpc_alter_context_resp`: :zeek:type:`event` Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` alter context response message.
:zeek:id:`dce_rpc_bind`: :zeek:type:`event`               Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` bind request message.
:zeek:id:`dce_rpc_bind_ack`: :zeek:type:`event`           Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` bind request ack message.
:zeek:id:`dce_rpc_message`: :zeek:type:`event`            Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` message.
:zeek:id:`dce_rpc_request`: :zeek:type:`event`            Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` request message.
:zeek:id:`dce_rpc_response`: :zeek:type:`event`           Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` response message.
========================================================= ==============================================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: dce_rpc_alter_context

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, uuid: :zeek:type:`string`, ver_major: :zeek:type:`count`, ver_minor: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` alter context request message.
   Since RPC offers the ability for a client to request connections to multiple endpoints, this event can occur
   multiple times for a single RPC message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :ctx_id: The context identifier of the data representation.
   

   :uuid: The string interpretted uuid of the endpoint being requested.
   

   :ver_major: The major version of the endpoint being requested.
   

   :ver_minor: The minor version of the endpoint being requested.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response dce_rpc_alter_context_resp

.. zeek:id:: dce_rpc_alter_context_resp

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` alter context response message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response dce_rpc_alter_context

.. zeek:id:: dce_rpc_bind

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, uuid: :zeek:type:`string`, ver_major: :zeek:type:`count`, ver_minor: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` bind request message.
   Since RPC offers the ability for a client to request connections to multiple endpoints, this event can occur
   multiple times for a single RPC message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :ctx_id: The context identifier of the data representation.
   

   :uuid: The string interpretted uuid of the endpoint being requested.
   

   :ver_major: The major version of the endpoint being requested.
   

   :ver_minor: The minor version of the endpoint being requested.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind_ack dce_rpc_request dce_rpc_response

.. zeek:id:: dce_rpc_bind_ack

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, sec_addr: :zeek:type:`string`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` bind request ack message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :sec_addr: Secondary address for the ack.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_request dce_rpc_response

.. zeek:id:: dce_rpc_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, fid: :zeek:type:`count`, ptype_id: :zeek:type:`count`, ptype: :zeek:type:`DCE_RPC::PType`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` message.
   

   :c: The connection.
   

   :is_orig: True if the message was sent by the originator of the TCP connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :ptype_id: Numeric representation of the procedure type of the message.
   

   :ptype: Enum representation of the prodecure type of the message.
   
   .. zeek:see:: dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response

.. zeek:id:: dce_rpc_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, opnum: :zeek:type:`count`, stub_len: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` request message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :ctx_id: The context identifier of the data representation.
   

   :opnum: Number of the RPC operation.
   

   :stub_len: Length of the data for the request.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_response

.. zeek:id:: dce_rpc_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, opnum: :zeek:type:`count`, stub_len: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` response message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :ctx_id: The context identifier of the data representation.

   :opnum: Number of the RPC operation.
   

   :stub_len: Length of the data for the response.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request


