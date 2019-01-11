:tocdepth: 3

base/bif/plugins/Bro_POP3.events.bif.bro
========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=============================================== ===================================================================
:bro:id:`pop3_data`: :bro:type:`event`          Generated for server-side multi-line responses on POP3 connections.
:bro:id:`pop3_login_failure`: :bro:type:`event` Generated for unsuccessful authentications on POP3 connections.
:bro:id:`pop3_login_success`: :bro:type:`event` Generated for successful authentications on POP3 connections.
:bro:id:`pop3_reply`: :bro:type:`event`         Generated for server-side replies to commands on POP3 connections.
:bro:id:`pop3_request`: :bro:type:`event`       Generated for client-side commands on POP3 connections.
:bro:id:`pop3_starttls`: :bro:type:`event`      Generated when a POP3 connection goes encrypted.
:bro:id:`pop3_unexpected`: :bro:type:`event`    Generated for errors encountered on POP3 sessions.
=============================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: pop3_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, data: :bro:type:`string`)

   Generated for server-side multi-line responses on POP3 connections. POP3
   connections use multi-line responses to send bulk data, such as the actual
   mails. This event is generated once for each line that's part of such a
   response.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :c: The connection.
   

   :is_orig: True if the data was sent by the originator of the TCP connection.
   

   :data: The data sent.
   
   .. bro:see:: pop3_login_failure pop3_login_success pop3_reply pop3_request
      pop3_unexpected
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pop3_login_failure

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, user: :bro:type:`string`, password: :bro:type:`string`)

   Generated for unsuccessful authentications on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :c: The connection.
   

   :is_orig: Always false.
   

   :user: The user name attempted for authentication. The event is only
         generated if a non-empty user name was used.
   

   :password: The password attempted for authentication.
   
   .. bro:see:: pop3_data pop3_login_success pop3_reply pop3_request
      pop3_unexpected
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pop3_login_success

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, user: :bro:type:`string`, password: :bro:type:`string`)

   Generated for successful authentications on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :c: The connection.
   

   :is_orig: Always false.
   

   :user: The user name used for authentication. The event is only generated if
         a non-empty user name was used.
   

   :password: The password used for authentication.
   
   .. bro:see:: pop3_data pop3_login_failure pop3_reply pop3_request
      pop3_unexpected
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pop3_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, cmd: :bro:type:`string`, msg: :bro:type:`string`)

   Generated for server-side replies to commands on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :cmd: The success indicator sent by the server. This corresponds to the
        first token on the line sent, and should be either ``OK`` or ``ERR``.
   

   :msg: The textual description the server sent along with *cmd*.
   
   .. bro:see:: pop3_data pop3_login_failure pop3_login_success pop3_request
      pop3_unexpected
   
   .. todo:: This event is receiving odd parameters, should unify.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pop3_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, command: :bro:type:`string`, arg: :bro:type:`string`)

   Generated for client-side commands on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :command: The command sent.
   

   :arg: The argument to the command.
   
   .. bro:see:: pop3_data pop3_login_failure pop3_login_success pop3_reply
      pop3_unexpected
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pop3_starttls

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when a POP3 connection goes encrypted. While POP3 is by default a
   clear-text protocol, extensions exist to switch to encryption. This event is
   generated if that happens and the analyzer then stops processing the
   connection.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :c: The connection.
   
   .. bro:see:: pop3_data pop3_login_failure pop3_login_success pop3_reply
      pop3_request pop3_unexpected
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pop3_unexpected

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`string`, detail: :bro:type:`string`)

   Generated for errors encountered on POP3 sessions. If the POP3 analyzer
   finds state transitions that do not conform to the protocol specification,
   or other situations it can't handle, it raises this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :c: The connection.
   

   :is_orig: True if the data was sent by the originator of the TCP connection.
   

   :msg: A textual description of the situation.
   

   :detail: The input that triggered the event.
   
   .. bro:see:: pop3_data pop3_login_failure pop3_login_success pop3_reply pop3_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


