:tocdepth: 3

base/bif/plugins/Zeek_POP3.events.bif.zeek
==========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================= ===================================================================
:zeek:id:`pop3_data`: :zeek:type:`event`          Generated for server-side multi-line responses on POP3 connections.
:zeek:id:`pop3_login_failure`: :zeek:type:`event` Generated for unsuccessful authentications on POP3 connections.
:zeek:id:`pop3_login_success`: :zeek:type:`event` Generated for successful authentications on POP3 connections.
:zeek:id:`pop3_reply`: :zeek:type:`event`         Generated for server-side replies to commands on POP3 connections.
:zeek:id:`pop3_request`: :zeek:type:`event`       Generated for client-side commands on POP3 connections.
:zeek:id:`pop3_starttls`: :zeek:type:`event`      Generated when a POP3 connection goes encrypted.
:zeek:id:`pop3_unexpected`: :zeek:type:`event`    Generated for errors encountered on POP3 sessions.
================================================= ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: pop3_data
   :source-code: base/bif/plugins/Zeek_POP3.events.bif.zeek 76 76

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, data: :zeek:type:`string`)

   Generated for server-side multi-line responses on POP3 connections. POP3
   connections use multi-line responses to send bulk data, such as the actual
   mails. This event is generated once for each line that's part of such a
   response.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the data was sent by the originator of the TCP connection.
   

   :param data: The data sent.
   
   .. zeek:see:: pop3_login_failure pop3_login_success pop3_reply pop3_request
      pop3_unexpected
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pop3_login_failure
   :source-code: base/bif/plugins/Zeek_POP3.events.bif.zeek 168 168

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, user: :zeek:type:`string`, password: :zeek:type:`string`)

   Generated for unsuccessful authentications on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :param c: The connection.
   

   :param is_orig: Always false.
   

   :param user: The user name attempted for authentication. The event is only
         generated if a non-empty user name was used.
   

   :param password: The password attempted for authentication.
   
   .. zeek:see:: pop3_data pop3_login_success pop3_reply pop3_request
      pop3_unexpected
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pop3_login_success
   :source-code: base/bif/plugins/Zeek_POP3.events.bif.zeek 144 144

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, user: :zeek:type:`string`, password: :zeek:type:`string`)

   Generated for successful authentications on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :param c: The connection.
   

   :param is_orig: Always false.
   

   :param user: The user name used for authentication. The event is only generated if
         a non-empty user name was used.
   

   :param password: The password used for authentication.
   
   .. zeek:see:: pop3_data pop3_login_failure pop3_reply pop3_request
      pop3_unexpected
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pop3_reply
   :source-code: base/bif/plugins/Zeek_POP3.events.bif.zeek 52 52

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, cmd: :zeek:type:`string`, msg: :zeek:type:`string`)

   Generated for server-side replies to commands on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param cmd: The success indicator sent by the server. This corresponds to the
        first token on the line sent, and should be either ``OK`` or ``ERR``.
   

   :param msg: The textual description the server sent along with *cmd*.
   
   .. zeek:see:: pop3_data pop3_login_failure pop3_login_success pop3_request
      pop3_unexpected
   
   .. todo:: This event is receiving odd parameters, should unify.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pop3_request
   :source-code: base/bif/plugins/Zeek_POP3.events.bif.zeek 25 25

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, command: :zeek:type:`string`, arg: :zeek:type:`string`)

   Generated for client-side commands on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param command: The command sent.
   

   :param arg: The argument to the command.
   
   .. zeek:see:: pop3_data pop3_login_failure pop3_login_success pop3_reply
      pop3_unexpected
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pop3_starttls
   :source-code: base/bif/plugins/Zeek_POP3.events.bif.zeek 120 120

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when a POP3 connection goes encrypted. While POP3 is by default a
   clear-text protocol, extensions exist to switch to encryption. This event is
   generated if that happens and the analyzer then stops processing the
   connection.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :param c: The connection.
   
   .. zeek:see:: pop3_data pop3_login_failure pop3_login_success pop3_reply
      pop3_request pop3_unexpected
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pop3_unexpected
   :source-code: base/bif/plugins/Zeek_POP3.events.bif.zeek 100 100

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`string`, detail: :zeek:type:`string`)

   Generated for errors encountered on POP3 sessions. If the POP3 analyzer
   finds state transitions that do not conform to the protocol specification,
   or other situations it can't handle, it raises this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the data was sent by the originator of the TCP connection.
   

   :param msg: A textual description of the situation.
   

   :param detail: The input that triggered the event.
   
   .. zeek:see:: pop3_data pop3_login_failure pop3_login_success pop3_reply pop3_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


