:tocdepth: 3

base/bif/plugins/Bro_DCE_RPC.events.bif.bro
===========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================= ==============================================================================================================================
:bro:id:`dce_rpc_alter_context`: :bro:type:`event`      Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` alter context request message.
:bro:id:`dce_rpc_alter_context_resp`: :bro:type:`event` Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` alter context response message.
:bro:id:`dce_rpc_bind`: :bro:type:`event`               Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` bind request message.
:bro:id:`dce_rpc_bind_ack`: :bro:type:`event`           Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` bind request ack message.
:bro:id:`dce_rpc_message`: :bro:type:`event`            Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` message.
:bro:id:`dce_rpc_request`: :bro:type:`event`            Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` request message.
:bro:id:`dce_rpc_response`: :bro:type:`event`           Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` response message.
======================================================= ==============================================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: dce_rpc_alter_context

   :Type: :bro:type:`event` (c: :bro:type:`connection`, fid: :bro:type:`count`, ctx_id: :bro:type:`count`, uuid: :bro:type:`string`, ver_major: :bro:type:`count`, ver_minor: :bro:type:`count`)

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
   
   .. bro:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response dce_rpc_alter_context_resp

.. bro:id:: dce_rpc_alter_context_resp

   :Type: :bro:type:`event` (c: :bro:type:`connection`, fid: :bro:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` alter context response message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   
   .. bro:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response dce_rpc_alter_context

.. bro:id:: dce_rpc_bind

   :Type: :bro:type:`event` (c: :bro:type:`connection`, fid: :bro:type:`count`, ctx_id: :bro:type:`count`, uuid: :bro:type:`string`, ver_major: :bro:type:`count`, ver_minor: :bro:type:`count`)

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
   
   .. bro:see:: dce_rpc_message dce_rpc_bind_ack dce_rpc_request dce_rpc_response

.. bro:id:: dce_rpc_bind_ack

   :Type: :bro:type:`event` (c: :bro:type:`connection`, fid: :bro:type:`count`, sec_addr: :bro:type:`string`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` bind request ack message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :sec_addr: Secondary address for the ack.
   
   .. bro:see:: dce_rpc_message dce_rpc_bind dce_rpc_request dce_rpc_response

.. bro:id:: dce_rpc_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, fid: :bro:type:`count`, ptype_id: :bro:type:`count`, ptype: :bro:type:`DCE_RPC::PType`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` message.
   

   :c: The connection.
   

   :is_orig: True if the message was sent by the originator of the TCP connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :ptype_id: Numeric representation of the procedure type of the message.
   

   :ptype: Enum representation of the prodecure type of the message.
   
   .. bro:see:: dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response

.. bro:id:: dce_rpc_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, fid: :bro:type:`count`, ctx_id: :bro:type:`count`, opnum: :bro:type:`count`, stub_len: :bro:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` request message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :ctx_id: The context identifier of the data representation.
   

   :opnum: Number of the RPC operation.
   

   :stub_len: Length of the data for the request.
   
   .. bro:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_response

.. bro:id:: dce_rpc_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, fid: :bro:type:`count`, ctx_id: :bro:type:`count`, opnum: :bro:type:`count`, stub_len: :bro:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` response message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :ctx_id: The context identifier of the data representation.

   :opnum: Number of the RPC operation.
   

   :stub_len: Length of the data for the response.
   
   .. bro:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request


