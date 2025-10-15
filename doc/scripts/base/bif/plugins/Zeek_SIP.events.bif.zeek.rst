:tocdepth: 3

base/bif/plugins/Zeek_SIP.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=============================================== ==========================================================================================================
:zeek:id:`sip_all_headers`: :zeek:type:`event`  Generated once for all :abbr:`SIP (Session Initiation Protocol)` headers from the originator or responder.
:zeek:id:`sip_begin_entity`: :zeek:type:`event` Generated at the beginning of a :abbr:`SIP (Session Initiation Protocol)` message.
:zeek:id:`sip_end_entity`: :zeek:type:`event`   Generated at the end of a :abbr:`SIP (Session Initiation Protocol)` message.
:zeek:id:`sip_header`: :zeek:type:`event`       Generated for each :abbr:`SIP (Session Initiation Protocol)` header.
:zeek:id:`sip_reply`: :zeek:type:`event`        Generated for :abbr:`SIP (Session Initiation Protocol)` replies, used in Voice over IP (VoIP).
:zeek:id:`sip_request`: :zeek:type:`event`      Generated for :abbr:`SIP (Session Initiation Protocol)` requests, used in Voice over IP (VoIP).
=============================================== ==========================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: sip_all_headers
   :source-code: base/bif/plugins/Zeek_SIP.events.bif.zeek 71 71

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, hlist: :zeek:type:`mime_header_list`)

   Generated once for all :abbr:`SIP (Session Initiation Protocol)` headers from the originator or responder.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :param c: The connection.
   

   :param is_orig: Whether the headers came from the originator.
   

   :param hlist: All the headers, and their values
   
   .. zeek:see:: sip_request sip_reply sip_header sip_begin_entity sip_end_entity

.. zeek:id:: sip_begin_entity
   :source-code: base/bif/plugins/Zeek_SIP.events.bif.zeek 86 86

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated at the beginning of a :abbr:`SIP (Session Initiation Protocol)` message.
   
   This event is generated as soon as a message's initial line has been parsed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :param c: The connection.
   

   :param is_orig: Whether the message came from the originator.
   
   .. zeek:see:: sip_request sip_reply sip_header sip_all_headers sip_end_entity

.. zeek:id:: sip_end_entity
   :source-code: base/bif/plugins/Zeek_SIP.events.bif.zeek 99 99

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated at the end of a :abbr:`SIP (Session Initiation Protocol)` message.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :param c: The connection.
   

   :param is_orig: Whether the message came from the originator.
   
   .. zeek:see:: sip_request sip_reply sip_header sip_all_headers sip_begin_entity

.. zeek:id:: sip_header
   :source-code: base/protocols/sip/main.zeek 193 273

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, name: :zeek:type:`string`, value: :zeek:type:`string`)

   Generated for each :abbr:`SIP (Session Initiation Protocol)` header.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :param c: The connection.
   

   :param is_orig: Whether the header came from the originator.
   

   :param name: Header name.
   

   :param value: Header value.
   
   .. zeek:see:: sip_request sip_reply sip_all_headers sip_begin_entity sip_end_entity

.. zeek:id:: sip_reply
   :source-code: base/protocols/sip/main.zeek 181 191

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`string`, code: :zeek:type:`count`, reason: :zeek:type:`string`)

   Generated for :abbr:`SIP (Session Initiation Protocol)` replies, used in Voice over IP (VoIP).
   
   This event is generated as soon as a reply's initial line has been parsed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :param c: The connection.
   

   :param version: The :abbr:`SIP (Session Initiation Protocol)` version in use.
   

   :param code: The response code.
   

   :param reason: Textual details for the response code.
   
   .. zeek:see:: sip_request sip_header sip_all_headers sip_begin_entity sip_end_entity

.. zeek:id:: sip_request
   :source-code: base/protocols/sip/main.zeek 170 179

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, method: :zeek:type:`string`, original_URI: :zeek:type:`string`, version: :zeek:type:`string`)

   Generated for :abbr:`SIP (Session Initiation Protocol)` requests, used in Voice over IP (VoIP).
   
   This event is generated as soon as a request's initial line has been parsed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :param c: The connection.
   

   :param method: The :abbr:`SIP (Session Initiation Protocol)` method extracted from the request (e.g., ``REGISTER``, ``NOTIFY``).
   

   :param original_URI: The unprocessed URI as specified in the request.
   

   :param version: The version number specified in the request (e.g., ``2.0``).
   
   .. zeek:see:: sip_reply sip_header sip_all_headers sip_begin_entity sip_end_entity


