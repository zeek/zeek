:tocdepth: 3

base/bif/plugins/Zeek_Login.events.bif.zeek
===========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
====================================================== =========================================================================
:zeek:id:`activating_encryption`: :zeek:type:`event`   Generated for Telnet sessions when encryption is activated.
:zeek:id:`authentication_accepted`: :zeek:type:`event` Generated when a Telnet authentication has been successful.
:zeek:id:`authentication_rejected`: :zeek:type:`event` Generated when a Telnet authentication has been unsuccessful.
:zeek:id:`authentication_skipped`: :zeek:type:`event`  Generated for Telnet/Rlogin sessions when a pattern match indicates
                                                       that no authentication is performed.
:zeek:id:`bad_option`: :zeek:type:`event`              Generated for an ill-formed or unrecognized Telnet option.
:zeek:id:`bad_option_termination`: :zeek:type:`event`  Generated for a Telnet option that's incorrectly terminated.
:zeek:id:`inconsistent_option`: :zeek:type:`event`     Generated for an inconsistent Telnet option.
:zeek:id:`login_confused`: :zeek:type:`event`          Generated when tracking of Telnet/Rlogin authentication failed.
:zeek:id:`login_confused_text`: :zeek:type:`event`     Generated after getting confused while tracking a Telnet/Rlogin
                                                       authentication dialog.
:zeek:id:`login_display`: :zeek:type:`event`           Generated for clients transmitting an X11 DISPLAY in a Telnet session.
:zeek:id:`login_failure`: :zeek:type:`event`           Generated for Telnet/Rlogin login failures.
:zeek:id:`login_input_line`: :zeek:type:`event`        Generated for lines of input on Telnet/Rlogin sessions.
:zeek:id:`login_output_line`: :zeek:type:`event`       Generated for lines of output on Telnet/Rlogin sessions.
:zeek:id:`login_prompt`: :zeek:type:`event`            Generated for clients transmitting a terminal prompt in a Telnet session.
:zeek:id:`login_success`: :zeek:type:`event`           Generated for successful Telnet/Rlogin logins.
:zeek:id:`login_terminal`: :zeek:type:`event`          Generated for clients transmitting a terminal type in a Telnet session.
:zeek:id:`rsh_reply`: :zeek:type:`event`               Generated for client side commands on an RSH connection.
:zeek:id:`rsh_request`: :zeek:type:`event`             Generated for client side commands on an RSH connection.
====================================================== =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: activating_encryption
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 367 367

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for Telnet sessions when encryption is activated. The Telnet
   protocol includes options for negotiating encryption. When such a series of
   options is successfully negotiated, the event engine generates this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param c: The connection.
   
   .. zeek:see:: authentication_accepted authentication_rejected authentication_skipped
      login_confused login_confused_text login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal

.. zeek:id:: authentication_accepted
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 279 279

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, c: :zeek:type:`connection`)

   Generated when a Telnet authentication has been successful. The Telnet
   protocol includes options for negotiating authentication. When such an
   option is sent from client to server and the server replies that it accepts
   the authentication, then the event engine generates this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param name: The authenticated name.
   

   :param c: The connection.
   
   .. zeek:see::  authentication_rejected authentication_skipped login_success
   
   .. note::  This event inspects the corresponding Telnet option
      while :zeek:id:`login_success` heuristically determines success by watching
      session data.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: authentication_rejected
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 305 305

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, c: :zeek:type:`connection`)

   Generated when a Telnet authentication has been unsuccessful. The Telnet
   protocol includes options for negotiating authentication. When such an option
   is sent from client to server and the server replies that it did not accept
   the authentication, then the event engine generates this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param name: The attempted authentication name.
   

   :param c: The connection.
   
   .. zeek:see:: authentication_accepted authentication_skipped login_failure
   
   .. note::  This event inspects the corresponding Telnet option
      while :zeek:id:`login_success` heuristically determines failure by watching
      session data.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: authentication_skipped
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 330 330

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for Telnet/Rlogin sessions when a pattern match indicates
   that no authentication is performed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param c: The connection.
   
   .. zeek:see:: authentication_accepted authentication_rejected direct_login_prompts
      get_login_state login_failure_msgs login_non_failure_msgs login_prompts
      login_success_msgs login_timeouts set_login_state
   
   .. note:: The login analyzer depends on a set of script-level variables that
      need to be configured with patterns identifying activity. This
      configuration has not yet been ported, and
      the analyzer is therefore not directly usable at the moment.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: bad_option
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 407 407

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for an ill-formed or unrecognized Telnet option.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param c: The connection.
   
   .. zeek:see:: inconsistent_option bad_option_termination authentication_accepted
      authentication_rejected authentication_skipped login_confused
      login_confused_text login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: bad_option_termination
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 427 427

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for a Telnet option that's incorrectly terminated.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param c: The connection.
   
   .. zeek:see:: inconsistent_option bad_option authentication_accepted
      authentication_rejected authentication_skipped login_confused
      login_confused_text login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: inconsistent_option
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 387 387

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for an inconsistent Telnet option. Telnet options are specified
   by the client and server stating which options they are willing to
   support vs. which they are not, and then instructing one another which in
   fact they should or should not use for the current connection. If the event
   engine sees a peer violate either what the other peer has instructed it to
   do, or what it itself offered in terms of options in the past, then the
   engine generates this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param c: The connection.
   
   .. zeek:see:: bad_option bad_option_termination  authentication_accepted
      authentication_rejected authentication_skipped login_confused
      login_confused_text login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal

.. zeek:id:: login_confused
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 195 195

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`string`, line: :zeek:type:`string`)

   Generated when tracking of Telnet/Rlogin authentication failed. As Zeek's
   *login* analyzer uses a number of heuristics to extract authentication
   information, it may become confused. If it can no longer correctly track
   the authentication dialog, it raises this event.
   

   :param c: The connection.
   

   :param msg: Gives the particular problem the heuristics detected (for example,
        ``multiple_login_prompts`` means that the engine saw several login
        prompts in a row, without the type-ahead from the client side presumed
        necessary to cause them)
   

   :param line: The line of text that caused the heuristics to conclude they were
         confused.
   
   .. zeek:see::  login_confused_text login_display login_failure login_input_line login_output_line
      login_prompt login_success login_terminal direct_login_prompts get_login_state
      login_failure_msgs login_non_failure_msgs login_prompts login_success_msgs
      login_timeouts set_login_state
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_confused_text
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 217 217

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, line: :zeek:type:`string`)

   Generated after getting confused while tracking a Telnet/Rlogin
   authentication dialog. The *login* analyzer generates this even for every
   line of user input after it has reported :zeek:id:`login_confused` for a
   connection.
   

   :param c: The connection.
   

   :param line: The line the user typed.
   
   .. zeek:see:: login_confused  login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal direct_login_prompts
      get_login_state login_failure_msgs login_non_failure_msgs login_prompts
      login_success_msgs login_timeouts set_login_state
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_display
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 253 253

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, display: :zeek:type:`string`)

   Generated for clients transmitting an X11 DISPLAY in a Telnet session. This
   information is extracted out of environment variables sent as Telnet options.
   

   :param c: The connection.
   

   :param display: The DISPLAY transmitted.
   
   .. zeek:see:: login_confused login_confused_text  login_failure login_input_line
      login_output_line login_prompt login_success login_terminal
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_failure
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 95 95

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, user: :zeek:type:`string`, client_user: :zeek:type:`string`, password: :zeek:type:`string`, line: :zeek:type:`string`)

   Generated for Telnet/Rlogin login failures. The *login* analyzer inspects
   Telnet/Rlogin sessions to heuristically extract username and password
   information as well as the text returned by the login server. This event is
   raised if a login attempt appears to have been unsuccessful.
   

   :param c: The connection.
   

   :param user: The user name tried.
   

   :param client_user: For Telnet connections, this is an empty string, but for Rlogin
         connections, it is the client name passed in the initial authentication
         information (to check against .rhosts).
   

   :param password:  The password tried.
   

   :param line:  The line of text that led the analyzer to conclude that the
          authentication had failed.
   
   .. zeek:see:: login_confused login_confused_text login_display login_input_line
      login_output_line login_prompt login_success login_terminal direct_login_prompts
      get_login_state login_failure_msgs login_non_failure_msgs login_prompts login_success_msgs
      login_timeouts set_login_state
   
   .. note:: The login analyzer depends on a set of script-level variables that
      need to be configured with patterns identifying login attempts. This
      configuration has not yet been ported, and
      the analyzer is therefore not directly usable at the moment.
   
   .. todo:: Zeeks's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_input_line
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 149 149

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, line: :zeek:type:`string`)

   Generated for lines of input on Telnet/Rlogin sessions. The line will have
   control characters (such as in-band Telnet options) removed.
   

   :param c: The connection.
   

   :param line: The input line.
   
   .. zeek:see:: login_confused login_confused_text login_display login_failure
      login_output_line login_prompt login_success login_terminal    rsh_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_output_line
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 167 167

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, line: :zeek:type:`string`)

   Generated for lines of output on Telnet/Rlogin sessions. The line will have
   control characters (such as in-band Telnet options) removed.
   

   :param c: The connection.
   

   :param line: The output line.
   
   .. zeek:see:: login_confused login_confused_text login_display login_failure
      login_input_line  login_prompt login_success login_terminal rsh_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_prompt
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 352 352

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, prompt: :zeek:type:`string`)

   Generated for clients transmitting a terminal prompt in a Telnet session.
   This information is extracted out of environment variables sent as Telnet
   options.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param c: The connection.
   

   :param prompt: The TTYPROMPT transmitted.
   
   .. zeek:see:: login_confused login_confused_text login_display login_failure
      login_input_line login_output_line  login_success login_terminal
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_success
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 131 131

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, user: :zeek:type:`string`, client_user: :zeek:type:`string`, password: :zeek:type:`string`, line: :zeek:type:`string`)

   Generated for successful Telnet/Rlogin logins. The *login* analyzer inspects
   Telnet/Rlogin sessions to heuristically extract username and password
   information as well as the text returned by the login server. This event is
   raised if a login attempt appears to have been successful.
   

   :param c: The connection.
   

   :param user: The user name used.
   

   :param client_user: For Telnet connections, this is an empty string, but for Rlogin
         connections, it is the client name passed in the initial authentication
         information (to check against .rhosts).
   

   :param password: The password used.
   

   :param line:  The line of text that led the analyzer to conclude that the
          authentication had succeeded.
   
   .. zeek:see:: login_confused login_confused_text login_display login_failure
      login_input_line login_output_line login_prompt login_terminal
      direct_login_prompts get_login_state login_failure_msgs login_non_failure_msgs
      login_prompts login_success_msgs login_timeouts set_login_state
   
   .. note:: The login analyzer depends on a set of script-level variables that
      need to be configured with patterns identifying login attempts. This
      configuration has not yet been ported, and
      the analyzer is therefore not directly usable at the moment.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_terminal
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 235 235

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, terminal: :zeek:type:`string`)

   Generated for clients transmitting a terminal type in a Telnet session.  This
   information is extracted out of environment variables sent as Telnet options.
   

   :param c: The connection.
   

   :param terminal: The TERM value transmitted.
   
   .. zeek:see:: login_confused login_confused_text login_display login_failure
      login_input_line login_output_line login_prompt login_success
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: rsh_reply
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 59 59

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, client_user: :zeek:type:`string`, server_user: :zeek:type:`string`, line: :zeek:type:`string`)

   Generated for client side commands on an RSH connection.
   
   See :rfc:`1258` for more information about the Rlogin/Rsh protocol.
   

   :param c: The connection.
   

   :param client_user: The client-side user name as sent in the initial protocol
         handshake.
   

   :param server_user: The server-side user name as sent in the initial protocol
         handshake.
   

   :param line: The command line sent in the request.
   
   .. zeek:see:: rsh_request login_confused login_confused_text login_display
      login_failure login_input_line login_output_line login_prompt login_success
      login_terminal
   
   .. note:: For historical reasons, these events are separate from the
      ``login_`` events. Ideally, they would all be handled uniquely.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: rsh_request
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 31 31

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, client_user: :zeek:type:`string`, server_user: :zeek:type:`string`, line: :zeek:type:`string`, new_session: :zeek:type:`bool`)

   Generated for client side commands on an RSH connection.
   
   See :rfc:`1258` for more information about the Rlogin/Rsh protocol.
   

   :param c: The connection.
   

   :param client_user: The client-side user name as sent in the initial protocol
         handshake.
   

   :param server_user: The server-side user name as sent in the initial protocol
         handshake.
   

   :param line: The command line sent in the request.
   

   :param new_session: True if this is the first command of the Rsh session.
   
   .. zeek:see:: rsh_reply login_confused login_confused_text login_display
      login_failure login_input_line login_output_line login_prompt login_success
      login_terminal
   
   .. note:: For historical reasons, these events are separate from the
      ``login_`` events. Ideally, they would all be handled uniquely.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


