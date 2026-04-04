:tocdepth: 3

base/protocols/imap/main.zeek
=============================
.. zeek:namespace:: IMAP


:Namespace: IMAP

Summary
~~~~~~~
Redefinable Options
###################
============================================================ ==========================
:zeek:id:`IMAP::ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for IMAP.
============================================================ ==========================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: IMAP::ports
   :source-code: base/protocols/imap/main.zeek 6 6

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            143/tcp
         }


   Well-known ports for IMAP.


