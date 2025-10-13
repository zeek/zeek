:tocdepth: 3

policy/protocols/smtp/software.zeek
===================================
.. zeek:namespace:: SMTP

This script feeds software detected through email into the software
framework.  Mail clients and webmail interfaces are the only thing
currently detected.

TODO:

* Find some heuristic to determine if email was sent through
  a MS Exchange webmail interface as opposed to a desktop client.

:Namespace: SMTP
:Imports: :doc:`base/frameworks/software/main.zeek </scripts/base/frameworks/software/main.zeek>`, :doc:`base/protocols/smtp/main.zeek </scripts/base/protocols/smtp/main.zeek>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================================= ===================================================================
:zeek:id:`SMTP::detect_clients_in_messages_from`: :zeek:type:`Host` :zeek:attr:`&redef` Assuming that local mail servers are more trustworthy with the
                                                                                        headers they insert into message envelopes, this default makes Zeek
                                                                                        not attempt to detect software in inbound message bodies.
:zeek:id:`SMTP::webmail_user_agents`: :zeek:type:`pattern` :zeek:attr:`&redef`          A regular expression to match USER-AGENT-like headers to find if a
                                                                                        message was sent with a webmail interface.
======================================================================================= ===================================================================

Redefinitions
#############
============================================== ======================================================================================================
:zeek:type:`SMTP::Info`: :zeek:type:`record`   
                                               
                                               :New Fields: :zeek:type:`SMTP::Info`
                                               
                                                 is_webmail: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                   Boolean indicator of if the message was sent through a
                                                   webmail interface.
:zeek:type:`Software::Type`: :zeek:type:`enum` 
                                               
                                               * :zeek:enum:`SMTP::MAIL_CLIENT`
                                               
                                               * :zeek:enum:`SMTP::MAIL_SERVER`
                                               
                                               * :zeek:enum:`SMTP::WEBMAIL_SERVER`
============================================== ======================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SMTP::detect_clients_in_messages_from
   :source-code: policy/protocols/smtp/software.zeek 36 36

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LOCAL_HOSTS``

   Assuming that local mail servers are more trustworthy with the
   headers they insert into message envelopes, this default makes Zeek
   not attempt to detect software in inbound message bodies.  If mail
   coming in from external addresses gives incorrect data in
   the Received headers, it could populate your SOFTWARE logging stream
   with incorrect data.  If you would like to detect mail clients for
   incoming messages (network traffic originating from a non-local
   address), set this variable to EXTERNAL_HOSTS or ALL_HOSTS.

.. zeek:id:: SMTP::webmail_user_agents
   :source-code: policy/protocols/smtp/software.zeek 40 40

   :Type: :zeek:type:`pattern`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         /^?((^?((^?((^?((^?((^?(^iPlanet Messenger)$?)|(^?(^Sun Java\(tm\) System Messenger Express)$?))$?)|(^?(\(IMP\))$?))$?)|(^?(^SquirrelMail)$?))$?)|(^?(^NeoMail)$?))$?)|(^?(ZimbraWebClient)$?))$?/


   A regular expression to match USER-AGENT-like headers to find if a
   message was sent with a webmail interface.


