:tocdepth: 3

base/bif/plugins/Zeek_MIME.events.bif.zeek
==========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================ =============================================================================
:zeek:id:`mime_all_data`: :zeek:type:`event`     Generated for passing on all data decoded from a single email MIME
                                                 message.
:zeek:id:`mime_all_headers`: :zeek:type:`event`  Generated for MIME headers extracted from email MIME entities, passing all
                                                 headers at once.
:zeek:id:`mime_begin_entity`: :zeek:type:`event` Generated when starting to parse an email MIME entity.
:zeek:id:`mime_content_hash`: :zeek:type:`event` Generated for decoded MIME entities extracted from email messages, passing on
                                                 their MD5 checksums.
:zeek:id:`mime_end_entity`: :zeek:type:`event`   Generated when finishing parsing an email MIME entity.
:zeek:id:`mime_entity_data`: :zeek:type:`event`  Generated for data decoded from an email MIME entity.
:zeek:id:`mime_event`: :zeek:type:`event`        Generated for errors found when decoding email MIME entities.
:zeek:id:`mime_one_header`: :zeek:type:`event`   Generated for individual MIME headers extracted from email MIME
                                                 entities.
:zeek:id:`mime_segment_data`: :zeek:type:`event` Generated for chunks of decoded MIME data from email MIME entities.
================================================ =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: mime_all_data
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 164 164

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, length: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for passing on all data decoded from a single email MIME
   message. If an email message has more than one MIME entity, this event
   combines all their data into a single value for analysis. Note that because
   of the potentially significant buffering necessary, using this event can be
   expensive.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   

   :param length: The length of *data*.
   

   :param data: The raw data of all MIME entities concatenated.
   
   .. zeek:see::  mime_all_headers mime_begin_entity mime_content_hash mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data
   
   .. note:: While Zeek also decodes MIME entities extracted from HTTP
      sessions, there's no corresponding event for that currently.

.. zeek:id:: mime_all_headers
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 85 85

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hlist: :zeek:type:`mime_header_list`)

   Generated for MIME headers extracted from email MIME entities, passing all
   headers at once.  MIME is a protocol-independent data format for encoding
   text and files, along with corresponding metadata, for transmission.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   

   :param hlist: A *table* containing all headers extracted from the current entity.
          The table is indexed by the position of the header (1 for the first,
          2 for the second, etc.).
   
   .. zeek:see:: mime_all_data  mime_begin_entity mime_content_hash mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data
      http_header  http_all_headers
   
   .. note:: Zeek also extracts MIME headers from HTTP sessions. For those,
      however, it raises :zeek:id:`http_header` instead.

.. zeek:id:: mime_begin_entity
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 21 21

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when starting to parse an email MIME entity. MIME is a
   protocol-independent data format for encoding text and files, along with
   corresponding metadata, for transmission. Zeek raises this event when it
   begins parsing a MIME entity extracted from an email protocol.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   
   .. zeek:see:: mime_all_data mime_all_headers  mime_content_hash mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data smtp_data
      http_begin_entity
   
   .. note:: Zeek also extracts MIME entities from HTTP sessions. For those,
      however, it raises :zeek:id:`http_begin_entity` instead.

.. zeek:id:: mime_content_hash
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 207 207

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, content_len: :zeek:type:`count`, hash_value: :zeek:type:`string`)

   Generated for decoded MIME entities extracted from email messages, passing on
   their MD5 checksums. Zeek computes the MD5 over the complete decoded data of
   each MIME entity.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   

   :param content_len: The length of the entity being hashed.
   

   :param hash_value: The MD5 hash.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data
   
   .. note:: While Zeek also decodes MIME entities extracted from HTTP
      sessions, there's no corresponding event for that currently.

.. zeek:id:: mime_end_entity
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 41 41

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when finishing parsing an email MIME entity.  MIME is a
   protocol-independent data format for encoding text and files, along with
   corresponding metadata, for transmission. Zeek raises this event when it
   finished parsing a MIME entity extracted from an email protocol.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_entity_data mime_event mime_one_header mime_segment_data smtp_data
      http_end_entity
   
   .. note:: Zeek also extracts MIME entities from HTTP sessions. For those,
      however, it raises :zeek:id:`http_end_entity` instead.

.. zeek:id:: mime_entity_data
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 140 140

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, length: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for data decoded from an email MIME entity. This event delivers
   the complete content of a single MIME entity with the quoted-printable and
   and base64 data decoded. In contrast, there is also :zeek:id:`mime_segment_data`,
   which passes on a sequence of data chunks as they come in. While
   ``mime_entity_data`` is more convenient to handle, ``mime_segment_data`` is
   more efficient as Zeek does not need to buffer the data. Thus, if possible,
   the latter should be preferred.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   

   :param length: The length of *data*.
   

   :param data: The raw data of the complete entity.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity  mime_event mime_one_header mime_segment_data
   
   .. note:: While Zeek also decodes MIME entities extracted from HTTP
      sessions, there's no corresponding event for that currently.

.. zeek:id:: mime_event
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 185 185

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, event_type: :zeek:type:`string`, detail: :zeek:type:`string`)

   Generated for errors found when decoding email MIME entities.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   

   :param event_type: A string describing the general category of the problem found
      (e.g., ``illegal format``).
   

   :param detail: Further more detailed description of the error.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data  mime_one_header mime_segment_data http_event
   
   .. note:: Zeek also extracts MIME headers from HTTP sessions. For those,
      however, it raises :zeek:id:`http_event` instead.

.. zeek:id:: mime_one_header
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 62 62

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, h: :zeek:type:`mime_header_rec`)

   Generated for individual MIME headers extracted from email MIME
   entities.  MIME is a protocol-independent data format for encoding text and
   files, along with corresponding metadata, for transmission.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   

   :param h: The parsed MIME header.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event  mime_segment_data
      http_header  http_all_headers
   
   .. note:: Zeek also extracts MIME headers from HTTP sessions. For those,
      however, it raises :zeek:id:`http_header` instead.

.. zeek:id:: mime_segment_data
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 114 114

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, length: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for chunks of decoded MIME data from email MIME entities.  MIME
   is a protocol-independent data format for encoding text and files, along with
   corresponding metadata, for transmission. As Zeek parses the data of an
   entity, it raises a sequence of these events, each coming as soon as a new
   chunk of data is available. In contrast, there is also
   :zeek:id:`mime_entity_data`, which passes all of an entities data at once
   in a single block. While the latter is more convenient to handle,
   ``mime_segment_data`` is more efficient as Zeek does not need to buffer
   the data. Thus, if possible, this event should be preferred.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   

   :param length: The length of *data*.
   

   :param data: The raw data of one segment of the current entity.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event mime_one_header http_entity_data
      mime_segment_length mime_segment_overlap_length
   
   .. note:: Zeek also extracts MIME data from HTTP sessions. For those,
      however, it raises :zeek:id:`http_entity_data` (sic!) instead.


