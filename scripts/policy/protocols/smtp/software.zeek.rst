:tocdepth: 3

policy/protocols/smtp/software.zeek
===================================
.. bro:namespace:: SMTP

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
==================================================================================== ===================================================================
:bro:id:`SMTP::detect_clients_in_messages_from`: :bro:type:`Host` :bro:attr:`&redef` Assuming that local mail servers are more trustworthy with the
                                                                                     headers they insert into message envelopes, this default makes Bro
                                                                                     not attempt to detect software in inbound message bodies.
:bro:id:`SMTP::webmail_user_agents`: :bro:type:`pattern` :bro:attr:`&redef`          A regular expression to match USER-AGENT-like headers to find if a 
                                                                                     message was sent with a webmail interface.
==================================================================================== ===================================================================

Redefinitions
#############
============================================ =
:bro:type:`SMTP::Info`: :bro:type:`record`   
:bro:type:`Software::Type`: :bro:type:`enum` 
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SMTP::detect_clients_in_messages_from

   :Type: :bro:type:`Host`
   :Attributes: :bro:attr:`&redef`
   :Default: ``LOCAL_HOSTS``

   Assuming that local mail servers are more trustworthy with the
   headers they insert into message envelopes, this default makes Bro
   not attempt to detect software in inbound message bodies.  If mail
   coming in from external addresses gives incorrect data in
   the Received headers, it could populate your SOFTWARE logging stream
   with incorrect data.  If you would like to detect mail clients for
   incoming messages (network traffic originating from a non-local
   address), set this variable to EXTERNAL_HOSTS or ALL_HOSTS.

.. bro:id:: SMTP::webmail_user_agents

   :Type: :bro:type:`pattern`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      /^?((^?((^?((^?((^?((^?(^iPlanet Messenger)$?)|(^?(^Sun Java\(tm\) System Messenger Express)$?))$?)|(^?(\(IMP\))$?))$?)|(^?(^SquirrelMail)$?))$?)|(^?(^NeoMail)$?))$?)|(^?(ZimbraWebClient)$?))$?/

   A regular expression to match USER-AGENT-like headers to find if a 
   message was sent with a webmail interface.


