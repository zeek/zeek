:tocdepth: 3

base/bif/plugins/Bro_SIP.events.bif.zeek
========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================= ==========================================================================================================
:bro:id:`sip_all_headers`: :bro:type:`event`  Generated once for all :abbr:`SIP (Session Initiation Protocol)` headers from the originator or responder.
:bro:id:`sip_begin_entity`: :bro:type:`event` Generated at the beginning of a :abbr:`SIP (Session Initiation Protocol)` message.
:bro:id:`sip_end_entity`: :bro:type:`event`   Generated at the end of a :abbr:`SIP (Session Initiation Protocol)` message.
:bro:id:`sip_header`: :bro:type:`event`       Generated for each :abbr:`SIP (Session Initiation Protocol)` header.
:bro:id:`sip_reply`: :bro:type:`event`        Generated for :abbr:`SIP (Session Initiation Protocol)` replies, used in Voice over IP (VoIP).
:bro:id:`sip_request`: :bro:type:`event`      Generated for :abbr:`SIP (Session Initiation Protocol)` requests, used in Voice over IP (VoIP).
============================================= ==========================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: sip_all_headers

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, hlist: :bro:type:`mime_header_list`)

   Generated once for all :abbr:`SIP (Session Initiation Protocol)` headers from the originator or responder.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :c: The connection.
   

   :is_orig: Whether the headers came from the originator.
   

   :hlist: All the headers, and their values
   
   .. bro:see:: sip_request sip_reply sip_header sip_begin_entity sip_end_entity

.. bro:id:: sip_begin_entity

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   Generated at the beginning of a :abbr:`SIP (Session Initiation Protocol)` message.
   
   This event is generated as soon as a message's initial line has been parsed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :c: The connection.
   

   :is_orig: Whether the message came from the originator.
   
   .. bro:see:: sip_request sip_reply sip_header sip_all_headers sip_end_entity

.. bro:id:: sip_end_entity

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   Generated at the end of a :abbr:`SIP (Session Initiation Protocol)` message.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :c: The connection.
   

   :is_orig: Whether the message came from the originator.
   
   .. bro:see:: sip_request sip_reply sip_header sip_all_headers sip_begin_entity

.. bro:id:: sip_header

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, name: :bro:type:`string`, value: :bro:type:`string`)

   Generated for each :abbr:`SIP (Session Initiation Protocol)` header.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :c: The connection.
   

   :is_orig: Whether the header came from the originator.
   

   :name: Header name.
   

   :value: Header value.
   
   .. bro:see:: sip_request sip_reply sip_all_headers sip_begin_entity sip_end_entity

.. bro:id:: sip_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`string`, code: :bro:type:`count`, reason: :bro:type:`string`)

   Generated for :abbr:`SIP (Session Initiation Protocol)` replies, used in Voice over IP (VoIP).
   
   This event is generated as soon as a reply's initial line has been parsed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :c: The connection.
   

   :version: The :abbr:`SIP (Session Initiation Protocol)` version in use.
   

   :code: The response code.
   

   :reason: Textual details for the response code.
   
   .. bro:see:: sip_request sip_header sip_all_headers sip_begin_entity sip_end_entity

.. bro:id:: sip_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, method: :bro:type:`string`, original_URI: :bro:type:`string`, version: :bro:type:`string`)

   Generated for :abbr:`SIP (Session Initiation Protocol)` requests, used in Voice over IP (VoIP).
   
   This event is generated as soon as a request's initial line has been parsed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :c: The connection.
   

   :method: The :abbr:`SIP (Session Initiation Protocol)` method extracted from the request (e.g., ``REGISTER``, ``NOTIFY``).
   

   :original_URI: The unprocessed URI as specified in the request.
   

   :version: The version number specified in the request (e.g., ``2.0``).
   
   .. bro:see:: sip_reply sip_header sip_all_headers sip_begin_entity sip_end_entity


