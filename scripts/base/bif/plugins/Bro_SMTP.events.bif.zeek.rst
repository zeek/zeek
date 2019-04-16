:tocdepth: 3

base/bif/plugins/Bro_SMTP.events.bif.zeek
=========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================ =================================================================================
:bro:id:`smtp_data`: :bro:type:`event`       Generated for DATA transmitted on SMTP sessions.
:bro:id:`smtp_reply`: :bro:type:`event`      Generated for server-side SMTP commands.
:bro:id:`smtp_request`: :bro:type:`event`    Generated for client-side SMTP commands.
:bro:id:`smtp_starttls`: :bro:type:`event`   Generated if a connection switched to using TLS using STARTTLS or X-ANONYMOUSTLS.
:bro:id:`smtp_unexpected`: :bro:type:`event` Generated for unexpected activity on SMTP sessions.
============================================ =================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smtp_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, data: :bro:type:`string`)

   Generated for DATA transmitted on SMTP sessions. This event is raised for
   subsequent chunks of raw data following the ``DATA`` SMTP command until the
   corresponding end marker ``.`` is seen. A handler may want to reassemble
   the pieces as they come in if stream-analysis is required.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__
   for more information about the SMTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the sender of the data is the originator of the TCP
         connection.
   

   :data: The raw data. Note that the size of each chunk is undefined and
         depends on specifics of the underlying TCP connection.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event mime_one_header mime_segment_data
      smtp_reply smtp_request skip_smtp_data
   
   .. note:: This event receives the unprocessed raw data. There is a separate
      set of ``mime_*`` events that strip out the outer MIME-layer of emails and
      provide structured access to their content.

.. bro:id:: smtp_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, code: :bro:type:`count`, cmd: :bro:type:`string`, msg: :bro:type:`string`, cont_resp: :bro:type:`bool`)

   Generated for server-side SMTP commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__
   for more information about the SMTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the sender of the command is the originator of the TCP
         connection. Note that this is not redundant: the SMTP ``TURN`` command
         allows client and server to flip roles on established SMTP sessions,
         and hence a "reply" might still come from the TCP-level originator. In
         practice, however, that will rarely happen as TURN is considered
         insecure and rarely used.
   

   :code: The reply's numerical code.
   

   :cmd: TODO.
   

   :msg: The reply's textual description.
   

   :cont_resp: True if the reply line is tagged as being continued to the next
         line. If so, further events will be raised and a handler may want to
         reassemble the pieces before processing the response any further.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event mime_one_header mime_segment_data
      smtp_data  smtp_request
   
   .. note:: Bro doesn't support the newer ETRN extension yet.

.. bro:id:: smtp_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, command: :bro:type:`string`, arg: :bro:type:`string`)

   Generated for client-side SMTP commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__
   for more information about the SMTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the sender of the command is the originator of the TCP
         connection. Note that this is not redundant: the SMTP ``TURN`` command
         allows client and server to flip roles on established SMTP sessions,
         and hence a "request" might still come from the TCP-level responder.
         In practice, however, that will rarely happen as TURN is considered
         insecure and rarely used.
   

   :command: The request's command, without any arguments.
   

   :arg: The request command's arguments.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event mime_one_header mime_segment_data
      smtp_data smtp_reply
   
   .. note:: Bro does not support the newer ETRN extension yet.

.. bro:id:: smtp_starttls

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated if a connection switched to using TLS using STARTTLS or X-ANONYMOUSTLS.
   After this event no more SMTP events will be raised for the connection. See the SSL
   analyzer for related SSL events, which will now be generated.
   

   :c: The connection.
   

.. bro:id:: smtp_unexpected

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`string`, detail: :bro:type:`string`)

   Generated for unexpected activity on SMTP sessions. The SMTP analyzer tracks
   the state of SMTP sessions and reports commands and other activity with this
   event that it sees even though it would not expect so at the current point
   of the communication.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__
   for more information about the SMTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the sender of the unexpected activity is the originator of
         the TCP connection.
   

   :msg: A descriptive message of what was unexpected.
   

   :detail: The actual SMTP line triggering the event.
   
   .. bro:see:: smtp_data  smtp_request smtp_reply


