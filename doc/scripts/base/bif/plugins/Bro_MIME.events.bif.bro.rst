:tocdepth: 3

base/bif/plugins/Bro_MIME.events.bif.bro
========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================== =============================================================================
:bro:id:`mime_all_data`: :bro:type:`event`     Generated for passing on all data decoded from a single email MIME
                                               message.
:bro:id:`mime_all_headers`: :bro:type:`event`  Generated for MIME headers extracted from email MIME entities, passing all
                                               headers at once.
:bro:id:`mime_begin_entity`: :bro:type:`event` Generated when starting to parse an email MIME entity.
:bro:id:`mime_content_hash`: :bro:type:`event` Generated for decoded MIME entities extracted from email messages, passing on
                                               their MD5 checksums.
:bro:id:`mime_end_entity`: :bro:type:`event`   Generated when finishing parsing an email MIME entity.
:bro:id:`mime_entity_data`: :bro:type:`event`  Generated for data decoded from an email MIME entity.
:bro:id:`mime_event`: :bro:type:`event`        Generated for errors found when decoding email MIME entities.
:bro:id:`mime_one_header`: :bro:type:`event`   Generated for individual MIME headers extracted from email MIME
                                               entities.
:bro:id:`mime_segment_data`: :bro:type:`event` Generated for chunks of decoded MIME data from email MIME entities.
============================================== =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: mime_all_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, length: :bro:type:`count`, data: :bro:type:`string`)

   Generated for passing on all data decoded from a single email MIME
   message. If an email message has more than one MIME entity, this event
   combines all their data into a single value for analysis. Note that because
   of the potentially significant buffering necessary, using this event can be
   expensive.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   

   :length: The length of *data*.
   

   :data: The raw data of all MIME entities concatenated.
   
   .. bro:see::  mime_all_headers mime_begin_entity mime_content_hash mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data
   
   .. note:: While Bro also decodes MIME entities extracted from HTTP
      sessions, there's no corresponding event for that currently.

.. bro:id:: mime_all_headers

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hlist: :bro:type:`mime_header_list`)

   Generated for MIME headers extracted from email MIME entities, passing all
   headers at once.  MIME is a protocol-independent data format for encoding
   text and files, along with corresponding metadata, for transmission.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   

   :hlist: A *table* containing all headers extracted from the current entity.
          The table is indexed by the position of the header (1 for the first,
          2 for the second, etc.).
   
   .. bro:see:: mime_all_data  mime_begin_entity mime_content_hash mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data
      http_header  http_all_headers
   
   .. note:: Bro also extracts MIME headers from HTTP sessions. For those,
      however, it raises :bro:id:`http_header` instead.

.. bro:id:: mime_begin_entity

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when starting to parse an email MIME entity. MIME is a
   protocol-independent data format for encoding text and files, along with
   corresponding metadata, for transmission. Bro raises this event when it
   begins parsing a MIME entity extracted from an email protocol.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   
   .. bro:see:: mime_all_data mime_all_headers  mime_content_hash mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data smtp_data
      http_begin_entity
   
   .. note:: Bro also extracts MIME entities from HTTP sessions. For those,
      however, it raises :bro:id:`http_begin_entity` instead.

.. bro:id:: mime_content_hash

   :Type: :bro:type:`event` (c: :bro:type:`connection`, content_len: :bro:type:`count`, hash_value: :bro:type:`string`)

   Generated for decoded MIME entities extracted from email messages, passing on
   their MD5 checksums. Bro computes the MD5 over the complete decoded data of
   each MIME entity.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   

   :content_len: The length of the entity being hashed.
   

   :hash_value: The MD5 hash.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data
   
   .. note:: While Bro also decodes MIME entities extracted from HTTP
      sessions, there's no corresponding event for that currently.

.. bro:id:: mime_end_entity

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when finishing parsing an email MIME entity.  MIME is a
   protocol-independent data format for encoding text and files, along with
   corresponding metadata, for transmission. Bro raises this event when it
   finished parsing a MIME entity extracted from an email protocol.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_entity_data mime_event mime_one_header mime_segment_data smtp_data
      http_end_entity
   
   .. note:: Bro also extracts MIME entities from HTTP sessions. For those,
      however, it raises :bro:id:`http_end_entity` instead.

.. bro:id:: mime_entity_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, length: :bro:type:`count`, data: :bro:type:`string`)

   Generated for data decoded from an email MIME entity. This event delivers
   the complete content of a single MIME entity with the quoted-printable and
   and base64 data decoded. In contrast, there is also :bro:id:`mime_segment_data`,
   which passes on a sequence of data chunks as they come in. While
   ``mime_entity_data`` is more convenient to handle, ``mime_segment_data`` is
   more efficient as Bro does not need to buffer the data. Thus, if possible,
   the latter should be preferred.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   

   :length: The length of *data*.
   

   :data: The raw data of the complete entity.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity  mime_event mime_one_header mime_segment_data
   
   .. note:: While Bro also decodes MIME entities extracted from HTTP
      sessions, there's no corresponding event for that currently.

.. bro:id:: mime_event

   :Type: :bro:type:`event` (c: :bro:type:`connection`, event_type: :bro:type:`string`, detail: :bro:type:`string`)

   Generated for errors found when decoding email MIME entities.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   

   :event_type: A string describing the general category of the problem found
      (e.g., ``illegal format``).
   

   :detail: Further more detailed description of the error.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data  mime_one_header mime_segment_data http_event
   
   .. note:: Bro also extracts MIME headers from HTTP sessions. For those,
      however, it raises :bro:id:`http_event` instead.

.. bro:id:: mime_one_header

   :Type: :bro:type:`event` (c: :bro:type:`connection`, h: :bro:type:`mime_header_rec`)

   Generated for individual MIME headers extracted from email MIME
   entities.  MIME is a protocol-independent data format for encoding text and
   files, along with corresponding metadata, for transmission.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   

   :h: The parsed MIME header.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event  mime_segment_data
      http_header  http_all_headers
   
   .. note:: Bro also extracts MIME headers from HTTP sessions. For those,
      however, it raises :bro:id:`http_header` instead.

.. bro:id:: mime_segment_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, length: :bro:type:`count`, data: :bro:type:`string`)

   Generated for chunks of decoded MIME data from email MIME entities.  MIME
   is a protocol-independent data format for encoding text and files, along with
   corresponding metadata, for transmission. As Bro parses the data of an
   entity, it raises a sequence of these events, each coming as soon as a new
   chunk of data is available. In contrast, there is also
   :bro:id:`mime_entity_data`, which passes all of an entities data at once
   in a single block. While the latter is more convenient to handle,
   ``mime_segment_data`` is more efficient as Bro does not need to buffer
   the data. Thus, if possible, this event should be preferred.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   

   :length: The length of *data*.
   

   :data: The raw data of one segment of the current entity.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event mime_one_header http_entity_data
      mime_segment_length mime_segment_overlap_length
   
   .. note:: Bro also extracts MIME data from HTTP sessions. For those,
      however, it raises :bro:id:`http_entity_data` (sic!) instead.


