:tocdepth: 3

base/bif/plugins/Zeek_HTTP.events.bif.zeek
==========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
====================================================== ========================================================================
:zeek:id:`http_all_headers`: :zeek:type:`event`        Generated for HTTP headers, passing on all headers of an HTTP message at
                                                       once.
:zeek:id:`http_begin_entity`: :zeek:type:`event`       Generated when starting to parse an HTTP body entity.
:zeek:id:`http_connection_upgrade`: :zeek:type:`event` Generated when a HTTP session is upgraded to a different protocol (e.g.
:zeek:id:`http_content_type`: :zeek:type:`event`       Generated for reporting an HTTP body's content type.
:zeek:id:`http_end_entity`: :zeek:type:`event`         Generated when finishing parsing an HTTP body entity.
:zeek:id:`http_entity_data`: :zeek:type:`event`        Generated when parsing an HTTP body entity, passing on the data.
:zeek:id:`http_event`: :zeek:type:`event`              Generated for errors found when decoding HTTP requests or replies.
:zeek:id:`http_header`: :zeek:type:`event`             Generated for HTTP headers.
:zeek:id:`http_message_done`: :zeek:type:`event`       Generated once at the end of parsing an HTTP message.
:zeek:id:`http_reply`: :zeek:type:`event`              Generated for HTTP replies.
:zeek:id:`http_request`: :zeek:type:`event`            Generated for HTTP requests.
:zeek:id:`http_stats`: :zeek:type:`event`              Generated at the end of an HTTP session to report statistics about it.
====================================================== ========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: http_all_headers
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 100 100

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, hlist: :zeek:type:`mime_header_list`)

   Generated for HTTP headers, passing on all headers of an HTTP message at
   once. Zeek supports persistent and pipelined HTTP sessions and raises
   corresponding events as it parses client/server dialogues.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the header was sent by the originator of the TCP connection.
   

   :param hlist: A *table* containing all headers extracted from the current entity.
          The table is indexed by the position of the header (1 for the first,
          2 for the second, etc.).
   
   .. zeek:see::  http_begin_entity http_content_type http_end_entity http_entity_data
      http_event http_header http_message_done http_reply http_request http_stats
      http_connection_upgrade
   
   .. note:: This event is also raised for headers found in nested body
      entities.

.. zeek:id:: http_begin_entity
   :source-code: base/protocols/http/entities.zeek 73 83

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated when starting to parse an HTTP body entity. This event is generated
   at least once for each non-empty (client or server) HTTP body; and
   potentially more than once if the body contains further nested MIME
   entities. Zeek raises this event just before it starts parsing each entity's
   content.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the entity was sent by the originator of the TCP
            connection.
   
   .. zeek:see:: http_all_headers  http_content_type http_end_entity http_entity_data
      http_event http_header http_message_done http_reply http_request http_stats
      mime_begin_entity http_connection_upgrade

.. zeek:id:: http_connection_upgrade
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 267 267

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, protocol: :zeek:type:`string`)

   Generated when a HTTP session is upgraded to a different protocol (e.g. websocket).
   This event is raised when a server replies with a HTTP 101 reply. No more HTTP events
   will be raised after this event.
   

   :param c: The connection.
   

   :param protocol: The protocol to which the connection is switching.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header http_message_done http_reply
      http_request

.. zeek:id:: http_content_type
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 196 196

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, ty: :zeek:type:`string`, subty: :zeek:type:`string`)

   Generated for reporting an HTTP body's content type.  This event is
   generated at the end of parsing an HTTP header, passing on the MIME
   type as specified by the ``Content-Type`` header. If that header is
   missing, this event is still raised with a default value of ``text/plain``.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the entity was sent by the originator of the TCP
            connection.
   

   :param ty: The main type.
   

   :param subty: The subtype.
   
   .. zeek:see:: http_all_headers http_begin_entity  http_end_entity http_entity_data
      http_event http_header http_message_done http_reply http_request http_stats
      http_connection_upgrade
   
   .. note:: This event is also raised for headers found in nested body
      entities.

.. zeek:id:: http_end_entity
   :source-code: base/protocols/http/entities.zeek 214 218

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated when finishing parsing an HTTP body entity. This event is generated
   at least once for each non-empty (client or server) HTTP body; and
   potentially more than once if the body contains further nested MIME
   entities. Zeek raises this event at the point when it has finished parsing an
   entity's content.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the entity was sent by the originator of the TCP
            connection.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_entity_data
      http_event http_header http_message_done http_reply http_request
      http_stats mime_end_entity http_connection_upgrade

.. zeek:id:: http_entity_data
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 170 170

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, length: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated when parsing an HTTP body entity, passing on the data. This event
   can potentially be raised many times for each entity, each time passing a
   chunk of the data of not further defined size.
   
   A common idiom for using this event is to first *reassemble* the data
   at the scripting layer by concatenating it to a successively growing
   string; and only perform further content analysis once the corresponding
   :zeek:id:`http_end_entity` event has been raised. Note, however, that doing so
   can be quite expensive for HTTP tranders. At the very least, one should
   impose an upper size limit on how much data is being buffered.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the entity was sent by the originator of the TCP
            connection.
   

   :param length: The length of *data*.
   

   :param data: One chunk of raw entity data.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_event http_header http_message_done http_reply http_request http_stats
      mime_entity_data http_entity_data_delivery_size skip_http_data
      http_connection_upgrade

.. zeek:id:: http_event
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 238 238

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, event_type: :zeek:type:`string`, detail: :zeek:type:`string`)

   Generated for errors found when decoding HTTP requests or replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param event_type: A string describing the general category of the problem found
               (e.g., ``illegal format``).
   

   :param detail: Further more detailed description of the error.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data  http_header http_message_done http_reply http_request
      http_stats mime_event http_connection_upgrade

.. zeek:id:: http_header
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 74 74

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, original_name: :zeek:type:`string`, name: :zeek:type:`string`, value: :zeek:type:`string`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, name: :zeek:type:`string`, value: :zeek:type:`string`)

   Generated for HTTP headers. Zeek supports persistent and pipelined HTTP
   sessions and raises corresponding events as it parses client/server
   dialogues.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the header was sent by the originator of the TCP connection.
   

   :param original_name: The name of the header (unaltered).
   

   :param name: The name of the header (converted to all uppercase).
   

   :param value: The value of the header.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event  http_message_done http_reply http_request
      http_stats http_connection_upgrade
   
   .. note:: This event is also raised for headers found in nested body
      entities.

.. zeek:id:: http_message_done
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 220 220

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, stat: :zeek:type:`http_message_stat`)

   Generated once at the end of parsing an HTTP message. Zeek supports persistent
   and pipelined HTTP sessions and raises corresponding events as it parses
   client/server dialogues. A "message" is one top-level HTTP entity, such as a
   complete request or reply. Each message can have further nested sub-entities
   inside. This event is raised once all sub-entities belonging to a top-level
   message have been processed (and their corresponding ``http_entity_*`` events
   generated).
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the entity was sent by the originator of the TCP
            connection.
   

   :param stat: Further meta information about the message.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header  http_reply http_request http_stats
      http_connection_upgrade

.. zeek:id:: http_reply
   :source-code: base/protocols/http/main.zeek 265 304

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`string`, code: :zeek:type:`count`, reason: :zeek:type:`string`)

   Generated for HTTP replies. Zeek supports persistent and pipelined HTTP
   sessions and raises corresponding events as it parses client/server
   dialogues. This event is generated as soon as a reply's initial line has
   been parsed, and before any :zeek:id:`http_header` events are raised.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param version: The version number specified in the reply (e.g., ``1.1``).
   

   :param code: The numerical response code returned by the server.
   

   :param reason: The textual description returned by the server along with *code*.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header http_message_done http_request
      http_stats http_connection_upgrade

.. zeek:id:: http_request
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 26 26

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, method: :zeek:type:`string`, original_URI: :zeek:type:`string`, unescaped_URI: :zeek:type:`string`, version: :zeek:type:`string`)

   Generated for HTTP requests. Zeek supports persistent and pipelined HTTP
   sessions and raises corresponding events as it parses client/server
   dialogues. This event is generated as soon as a request's initial line has
   been parsed, and before any :zeek:id:`http_header` events are raised.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param method: The HTTP method extracted from the request (e.g., ``GET``, ``POST``).
   

   :param original_URI: The unprocessed URI as specified in the request.
   

   :param unescaped_URI: The URI with all percent-encodings decoded.
   

   :param version: The version number specified in the request (e.g., ``1.1``).
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header http_message_done http_reply http_stats
      truncate_http_URI http_connection_upgrade

.. zeek:id:: http_stats
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 253 253

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, stats: :zeek:type:`http_stats_rec`)

   Generated at the end of an HTTP session to report statistics about it. This
   event is raised after all of an HTTP session's requests and replies have been
   fully processed.
   

   :param c: The connection.
   

   :param stats: Statistics summarizing HTTP-level properties of the finished
          connection.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header http_message_done http_reply
      http_request http_connection_upgrade


