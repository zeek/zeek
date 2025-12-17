:tocdepth: 3

base/protocols/finger/main.zeek
===============================
.. zeek:namespace:: Finger

Implements base functionality for Finger analysis. We currently do not generate
a log file, but just configure the analyzer.

:Namespace: Finger

Summary
~~~~~~~
Redefinable Options
###################
============================================================== ============================
:zeek:id:`Finger::ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for Finger.
============================================================== ============================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Finger::ports
   :source-code: base/protocols/finger/main.zeek 8 8

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            79/tcp
         }


   Well-known ports for Finger.


