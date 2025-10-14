:tocdepth: 3

base/bif/plugins/Zeek_DCE_RPC.events.bif.zeek
=============================================
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
:zeek:id:`dce_rpc_request_stub`: :zeek:type:`event`       Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` request message.
:zeek:id:`dce_rpc_response`: :zeek:type:`event`           Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` response message.
:zeek:id:`dce_rpc_response_stub`: :zeek:type:`event`      Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` response message.
========================================================= ==============================================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: dce_rpc_alter_context
   :source-code: base/protocols/dce-rpc/main.zeek 125 137

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, uuid: :zeek:type:`string`, ver_major: :zeek:type:`count`, ver_minor: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` alter context request message.
   Since RPC offers the ability for a client to request connections to multiple endpoints, this event can occur
   multiple times for a single RPC message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param ctx_id: The context identifier of the data representation.
   

   :param uuid: The string interpreted uuid of the endpoint being requested.
   

   :param ver_major: The major version of the endpoint being requested.
   

   :param ver_minor: The minor version of the endpoint being requested.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response dce_rpc_alter_context_resp

.. zeek:id:: dce_rpc_alter_context_resp
   :source-code: base/protocols/dce-rpc/main.zeek 150 153

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` alter context response message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response dce_rpc_alter_context

.. zeek:id:: dce_rpc_bind
   :source-code: base/protocols/dce-rpc/main.zeek 111 123

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, uuid: :zeek:type:`string`, ver_major: :zeek:type:`count`, ver_minor: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` bind request message.
   Since RPC offers the ability for a client to request connections to multiple endpoints, this event can occur
   multiple times for a single RPC message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param ctx_id: The context identifier of the data representation.
   

   :param uuid: The string interpreted uuid of the endpoint being requested.
   

   :param ver_major: The major version of the endpoint being requested.
   

   :param ver_minor: The minor version of the endpoint being requested.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind_ack dce_rpc_request dce_rpc_response

.. zeek:id:: dce_rpc_bind_ack
   :source-code: base/protocols/dce-rpc/main.zeek 139 148

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, sec_addr: :zeek:type:`string`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` bind request ack message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param sec_addr: Secondary address for the ack.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_request dce_rpc_response

.. zeek:id:: dce_rpc_message
   :source-code: base/bif/plugins/Zeek_DCE_RPC.events.bif.zeek 19 19

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, fid: :zeek:type:`count`, ptype_id: :zeek:type:`count`, ptype: :zeek:type:`DCE_RPC::PType`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` message.
   

   :param c: The connection.
   

   :param is_orig: True if the message was sent by the originator of the TCP connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param ptype_id: Numeric representation of the procedure type of the message.
   

   :param ptype: Enum representation of the procedure type of the message.
   
   .. zeek:see:: dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response

.. zeek:id:: dce_rpc_request
   :source-code: base/protocols/dce-rpc/main.zeek 155 163

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, opnum: :zeek:type:`count`, stub_len: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` request message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param ctx_id: The context identifier of the data representation.
   

   :param opnum: Number of the RPC operation.
   

   :param stub_len: Length of the data for the request.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_response dce_rpc_request_stub

.. zeek:id:: dce_rpc_request_stub
   :source-code: base/bif/plugins/Zeek_DCE_RPC.events.bif.zeek 143 143

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, opnum: :zeek:type:`count`, stub: :zeek:type:`string`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` request message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param ctx_id: The context identifier of the data representation.
   

   :param opnum: Number of the RPC operation.
   

   :param stub: The data for the request.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_response_stub dce_rpc_request

.. zeek:id:: dce_rpc_response
   :source-code: base/bif/plugins/Zeek_DCE_RPC.events.bif.zeek 125 125

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, opnum: :zeek:type:`count`, stub_len: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` response message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param ctx_id: The context identifier of the data representation.

   :param opnum: Number of the RPC operation.
   

   :param stub_len: Length of the data for the response.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response_stub

.. zeek:id:: dce_rpc_response_stub
   :source-code: base/bif/plugins/Zeek_DCE_RPC.events.bif.zeek 161 161

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, opnum: :zeek:type:`count`, stub: :zeek:type:`string`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` response message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param ctx_id: The context identifier of the data representation.

   :param opnum: Number of the RPC operation.
   

   :param stub: The data for the response.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request_stub dce_rpc_response


