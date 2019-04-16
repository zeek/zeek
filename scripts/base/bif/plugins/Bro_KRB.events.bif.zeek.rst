:tocdepth: 3

base/bif/plugins/Bro_KRB.events.bif.zeek
========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================= ==================================================================
:bro:id:`krb_ap_request`: :bro:type:`event`   A Kerberos 5 ``Authentication Header (AP) Request`` as defined
                                              in :rfc:`4120`.
:bro:id:`krb_ap_response`: :bro:type:`event`  A Kerberos 5 ``Authentication Header (AP) Response`` as defined
                                              in :rfc:`4120`.
:bro:id:`krb_as_request`: :bro:type:`event`   A Kerberos 5 ``Authentication Server (AS) Request`` as defined
                                              in :rfc:`4120`.
:bro:id:`krb_as_response`: :bro:type:`event`  A Kerberos 5 ``Authentication Server (AS) Response`` as defined
                                              in :rfc:`4120`.
:bro:id:`krb_cred`: :bro:type:`event`         A Kerberos 5 ``Credential Message`` as defined in :rfc:`4120`.
:bro:id:`krb_error`: :bro:type:`event`        A Kerberos 5 ``Error Message`` as defined in :rfc:`4120`.
:bro:id:`krb_priv`: :bro:type:`event`         A Kerberos 5 ``Private Message`` as defined in :rfc:`4120`.
:bro:id:`krb_safe`: :bro:type:`event`         A Kerberos 5 ``Safe Message`` as defined in :rfc:`4120`.
:bro:id:`krb_tgs_request`: :bro:type:`event`  A Kerberos 5 ``Ticket Granting Service (TGS) Request`` as defined
                                              in :rfc:`4120`.
:bro:id:`krb_tgs_response`: :bro:type:`event` A Kerberos 5 ``Ticket Granting Service (TGS) Response`` as defined
                                              in :rfc:`4120`.
============================================= ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: krb_ap_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, ticket: :bro:type:`KRB::Ticket`, opts: :bro:type:`KRB::AP_Options`)

   A Kerberos 5 ``Authentication Header (AP) Request`` as defined
   in :rfc:`4120`. This message contains authentication information
   that should be part of the first message in an authenticated
   transaction.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :ticket: The Kerberos ticket being used for authentication.
   

   :opts: A Kerberos AP options data structure.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. bro:id:: krb_ap_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   A Kerberos 5 ``Authentication Header (AP) Response`` as defined
   in :rfc:`4120`. This is used if mutual authentication is desired.
   All of the interesting information in here is encrypted, so the event
   doesn't have much useful data, but it's provided in case it's important
   to know that this message was sent.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_priv krb_safe krb_cred krb_error

.. bro:id:: krb_as_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`KRB::KDC_Request`)

   A Kerberos 5 ``Authentication Server (AS) Request`` as defined
   in :rfc:`4120`. The AS request contains a username of the client
   requesting authentication, and returns an AS reply with an
   encrypted Ticket Granting Ticket (TGT) for that user. The TGT
   can then be used to request further tickets for other services.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :msg: A Kerberos KDC request message data structure.
   
   .. bro:see:: krb_as_response krb_tgs_request krb_tgs_response krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. bro:id:: krb_as_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`KRB::KDC_Response`)

   A Kerberos 5 ``Authentication Server (AS) Response`` as defined
   in :rfc:`4120`. Following the AS request for a user, an AS reply
   contains an encrypted Ticket Granting Ticket (TGT) for that user.
   The TGT can then be used to request further tickets for other services.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :msg: A Kerberos KDC reply message data structure.
   
   .. bro:see:: krb_as_request krb_tgs_request krb_tgs_response krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. bro:id:: krb_cred

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, tickets: :bro:type:`KRB::Ticket_Vector`)

   A Kerberos 5 ``Credential Message`` as defined in :rfc:`4120`. This is
   a private (encrypted) message to forward credentials.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :is_orig: Whether the originator of the connection sent this message.
   

   :tickets: Tickets obtained from the KDC that are being forwarded.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_priv krb_safe krb_error

.. bro:id:: krb_error

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`KRB::Error_Msg`)

   A Kerberos 5 ``Error Message`` as defined in :rfc:`4120`.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :msg: A Kerberos error message data structure.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_priv krb_safe krb_cred

.. bro:id:: krb_priv

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   A Kerberos 5 ``Private Message`` as defined in :rfc:`4120`. This
   is a private (encrypted) application message, so the event doesn't
   have much useful data, but it's provided in case it's important to
   know that this message was sent.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :is_orig: Whether the originator of the connection sent this message.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_safe krb_cred krb_error

.. bro:id:: krb_safe

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`KRB::SAFE_Msg`)

   A Kerberos 5 ``Safe Message`` as defined in :rfc:`4120`. This is a
   safe (checksummed) application message.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :is_orig: Whether the originator of the connection sent this message.
   

   :msg: A Kerberos SAFE message data structure.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_priv krb_cred krb_error

.. bro:id:: krb_tgs_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`KRB::KDC_Request`)

   A Kerberos 5 ``Ticket Granting Service (TGS) Request`` as defined
   in :rfc:`4120`. Following the Authentication Server exchange, if
   successful, the client now has a Ticket Granting Ticket (TGT). To
   authenticate to a Kerberized service, the client requests a Service
   Ticket, which will be returned in the TGS reply.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :msg: A Kerberos KDC request message data structure.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_response krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. bro:id:: krb_tgs_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`KRB::KDC_Response`)

   A Kerberos 5 ``Ticket Granting Service (TGS) Response`` as defined
   in :rfc:`4120`. This message returns a Service Ticket to the client,
   which is encrypted with the service's long-term key, and which the
   client can use to authenticate to that service.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :msg: A Kerberos KDC reply message data structure.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_request krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error


