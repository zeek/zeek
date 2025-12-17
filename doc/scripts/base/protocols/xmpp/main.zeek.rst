:tocdepth: 3

base/protocols/xmpp/main.zeek
=============================
.. zeek:namespace:: XMPP


:Namespace: XMPP

Summary
~~~~~~~
Redefinable Options
###################
============================================================ ==========================
:zeek:id:`XMPP::ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for XMPP.
============================================================ ==========================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: XMPP::ports
   :source-code: base/protocols/xmpp/main.zeek 6 6

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            5222/tcp,
            5269/tcp
         }


   Well-known ports for XMPP.


