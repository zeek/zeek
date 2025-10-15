:tocdepth: 3

base/bif/plugins/Zeek_KRB.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=============================================== ==================================================================
:zeek:id:`krb_ap_request`: :zeek:type:`event`   A Kerberos 5 ``Authentication Header (AP) Request`` as defined
                                                in :rfc:`4120`.
:zeek:id:`krb_ap_response`: :zeek:type:`event`  A Kerberos 5 ``Authentication Header (AP) Response`` as defined
                                                in :rfc:`4120`.
:zeek:id:`krb_as_request`: :zeek:type:`event`   A Kerberos 5 ``Authentication Server (AS) Request`` as defined
                                                in :rfc:`4120`.
:zeek:id:`krb_as_response`: :zeek:type:`event`  A Kerberos 5 ``Authentication Server (AS) Response`` as defined
                                                in :rfc:`4120`.
:zeek:id:`krb_cred`: :zeek:type:`event`         A Kerberos 5 ``Credential Message`` as defined in :rfc:`4120`.
:zeek:id:`krb_error`: :zeek:type:`event`        A Kerberos 5 ``Error Message`` as defined in :rfc:`4120`.
:zeek:id:`krb_priv`: :zeek:type:`event`         A Kerberos 5 ``Private Message`` as defined in :rfc:`4120`.
:zeek:id:`krb_safe`: :zeek:type:`event`         A Kerberos 5 ``Safe Message`` as defined in :rfc:`4120`.
:zeek:id:`krb_tgs_request`: :zeek:type:`event`  A Kerberos 5 ``Ticket Granting Service (TGS) Request`` as defined
                                                in :rfc:`4120`.
:zeek:id:`krb_tgs_response`: :zeek:type:`event` A Kerberos 5 ``Ticket Granting Service (TGS) Response`` as defined
                                                in :rfc:`4120`.
=============================================== ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: krb_ap_request
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 90 90

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, ticket: :zeek:type:`KRB::Ticket`, opts: :zeek:type:`KRB::AP_Options`)

   A Kerberos 5 ``Authentication Header (AP) Request`` as defined
   in :rfc:`4120`. This message contains authentication information
   that should be part of the first message in an authenticated
   transaction.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param ticket: The Kerberos ticket being used for authentication.
   

   :param opts: A Kerberos AP options data structure.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. zeek:id:: krb_ap_response
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 106 106

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   A Kerberos 5 ``Authentication Header (AP) Response`` as defined
   in :rfc:`4120`. This is used if mutual authentication is desired.
   All of the interesting information in here is encrypted, so the event
   doesn't have much useful data, but it's provided in case it's important
   to know that this message was sent.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_priv krb_safe krb_cred krb_error

.. zeek:id:: krb_as_request
   :source-code: base/protocols/krb/main.zeek 145 168

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`KRB::KDC_Request`)

   A Kerberos 5 ``Authentication Server (AS) Request`` as defined
   in :rfc:`4120`. The AS request contains a username of the client
   requesting authentication, and returns an AS reply with an
   encrypted Ticket Granting Ticket (TGT) for that user. The TGT
   can then be used to request further tickets for other services.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param msg: A Kerberos KDC request message data structure.
   
   .. zeek:see:: krb_as_response krb_tgs_request krb_tgs_response krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. zeek:id:: krb_as_response
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 36 36

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`KRB::KDC_Response`)

   A Kerberos 5 ``Authentication Server (AS) Response`` as defined
   in :rfc:`4120`. Following the AS request for a user, an AS reply
   contains an encrypted Ticket Granting Ticket (TGT) for that user.
   The TGT can then be used to request further tickets for other services.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param msg: A Kerberos KDC reply message data structure.
   
   .. zeek:see:: krb_as_request krb_tgs_request krb_tgs_response krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. zeek:id:: krb_cred
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 157 157

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, tickets: :zeek:type:`KRB::Ticket_Vector`)

   A Kerberos 5 ``Credential Message`` as defined in :rfc:`4120`. This is
   a private (encrypted) message to forward credentials.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param is_orig: Whether the originator of the connection sent this message.
   

   :param tickets: Tickets obtained from the KDC that are being forwarded.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_priv krb_safe krb_error

.. zeek:id:: krb_error
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 171 171

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`KRB::Error_Msg`)

   A Kerberos 5 ``Error Message`` as defined in :rfc:`4120`.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param msg: A Kerberos error message data structure.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_priv krb_safe krb_cred

.. zeek:id:: krb_priv
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 123 123

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   A Kerberos 5 ``Private Message`` as defined in :rfc:`4120`. This
   is a private (encrypted) application message, so the event doesn't
   have much useful data, but it's provided in case it's important to
   know that this message was sent.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param is_orig: Whether the originator of the connection sent this message.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_safe krb_cred krb_error

.. zeek:id:: krb_safe
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 140 140

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`KRB::SAFE_Msg`)

   A Kerberos 5 ``Safe Message`` as defined in :rfc:`4120`. This is a
   safe (checksummed) application message.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param is_orig: Whether the originator of the connection sent this message.
   

   :param msg: A Kerberos SAFE message data structure.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_priv krb_cred krb_error

.. zeek:id:: krb_tgs_request
   :source-code: base/protocols/krb/main.zeek 197 215

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`KRB::KDC_Request`)

   A Kerberos 5 ``Ticket Granting Service (TGS) Request`` as defined
   in :rfc:`4120`. Following the Authentication Server exchange, if
   successful, the client now has a Ticket Granting Ticket (TGT). To
   authenticate to a Kerberized service, the client requests a Service
   Ticket, which will be returned in the TGS reply.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param msg: A Kerberos KDC request message data structure.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_response krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. zeek:id:: krb_tgs_response
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 71 71

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`KRB::KDC_Response`)

   A Kerberos 5 ``Ticket Granting Service (TGS) Response`` as defined
   in :rfc:`4120`. This message returns a Service Ticket to the client,
   which is encrypted with the service's long-term key, and which the
   client can use to authenticate to that service.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param msg: A Kerberos KDC reply message data structure.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_request krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error


